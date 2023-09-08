#![no_std]
#![feature(allocator_api)]

extern crate alloc;

use core::ops::Div;
use core::ptr::NonNull;

use alloc::alloc::{Allocator, Global};
use alloc::boxed::Box;

pub mod checksum;
pub mod data_link;
pub mod network;
pub mod transport;

// Generics:
//
// U: Upper
// L: Lower
// K: Much Lower

#[macro_export]
macro_rules! impl_stack {
    (@make $name:ty {
        fn write_stage2(&self, $mem:ident: NonNull<u8>, $payload_len:ident: usize) $code:block
    }) => {
        impl<L: $crate::Stack<$name>> core::ops::Div<L> for $name {
            type Output = L::Output;

            #[inline]
            fn div(self, rhs: L) -> Self::Output {
                rhs.stack(self)
            }
        }

        unsafe impl $crate::Protocol for $name {
            #[inline]
            fn write_len(&self) -> usize {
                core::mem::size_of::<Self>()
            }

            #[inline]
            unsafe fn write_stage1(&self, mem: core::ptr::NonNull<u8>) {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self,
                        mem.as_ptr().cast::<Self>(),
                        1,
                    );
                }
            }

            unsafe fn write_stage2(&self, $mem: core::ptr::NonNull<u8>, $payload_len: usize) $code
        }
    }
}

pub trait IntoBoxedBytes<A: Allocator = Global> {
    fn into_boxed_bytes(self) -> Box<[u8], A>;
}

trait PointerExtension {
    unsafe fn add(self, count: usize) -> Self;
    unsafe fn sub(self, count: usize) -> Self;
}

impl<T> PointerExtension for NonNull<T> {
    #[inline]
    unsafe fn add(self, count: usize) -> Self {
        NonNull::new_unchecked(self.as_ptr().add(count))
    }

    #[inline]
    unsafe fn sub(self, count: usize) -> Self {
        NonNull::new_unchecked(self.as_ptr().sub(count))
    }
}

// impl for [T; N]
unsafe impl<const N: usize, T> StackingAnchor<[T; N]> for [T; N] {}
unsafe impl<'a, const N: usize, T, U: Protocol> StackingAnchor<[T; N]>
    for crate::Stacked<'a, U, [T; N]>
{
}

impl<const N: usize, T, U: Protocol> Stack<U> for [T; N]
where
    U: 'static,
{
    type Output = Stacked<'static, U, Self>;

    fn stack(self, lhs: U) -> Self::Output {
        Self::Output {
            upper: MaybeOwned::Owned(lhs),
            lower: self,
        }
    }
}

unsafe impl<const N: usize, T> Protocol for [T; N] {
    #[inline]
    fn write_len(&self) -> usize {
        core::mem::size_of::<Self>()
    }

    unsafe fn write_stage1(&self, mem: NonNull<u8>) {
        unsafe {
            core::ptr::copy_nonoverlapping(self.as_ptr(), mem.cast::<T>().as_ptr(), N);
        }
    }

    unsafe fn write_stage2(&self, _mem: NonNull<u8>, _payload_len: usize) {}
}

// impl for &[T]
unsafe impl<T> StackingAnchor<&[T]> for &[T] {}
unsafe impl<'a, T, U: Protocol> StackingAnchor<&[T]> for crate::Stacked<'a, U, &'a [T]> {}

impl<T, U: Protocol> Stack<U> for &[T]
where
    U: 'static,
{
    type Output = Stacked<'static, U, Self>;

    fn stack(self, lhs: U) -> Self::Output {
        Self::Output {
            upper: MaybeOwned::Owned(lhs),
            lower: self,
        }
    }
}

unsafe impl<T> Protocol for &[T] {
    #[inline]
    fn write_len(&self) -> usize {
        self.len()
    }

    unsafe fn write_stage1(&self, mem: NonNull<u8>) {
        unsafe {
            core::ptr::copy_nonoverlapping(self.as_ptr(), mem.cast::<T>().as_ptr(), self.len());
        }
    }

    unsafe fn write_stage2(&self, _mem: NonNull<u8>, _payload_len: usize) {}
}

pub unsafe trait Protocol {
    /// Returns the write length in bytes.
    fn write_len(&self) -> usize;
    unsafe fn write_stage1(&self, mem: NonNull<u8>);
    unsafe fn write_stage2(&self, mem: NonNull<u8>, payload_len: usize);
}

unsafe trait StackingAnchor<U: Protocol>: Protocol {}

pub trait Stack<U: Protocol> {
    type Output;

    fn stack(self, lhs: U) -> Self::Output;
}

pub unsafe trait IsSafeToWrite: Protocol {}

pub enum MaybeOwned<'a, T> {
    Owned(T),
    Borrowed(&'a T),
}

impl<'a, T> MaybeOwned<'a, T> {
    #[inline]
    pub fn as_ref(&self) -> &T {
        match self {
            Self::Owned(t) => &t,
            Self::Borrowed(_) => unreachable!(),
        }
    }
}

pub struct Stacked<'a, U: Protocol, L: Protocol> {
    pub upper: MaybeOwned<'a, U>,
    pub lower: L,
}

impl<'a, U: Protocol, L: Protocol, K: Stack<Stacked<'a, U, L>>> Div<K> for Stacked<'a, U, L> {
    type Output = K::Output;

    #[inline]
    fn div(self, rhs: K) -> Self::Output {
        rhs.stack(self)
    }
}

unsafe impl<'a, U: Protocol, L: Protocol> Protocol for Stacked<'a, U, L> {
    #[inline]
    fn write_len(&self) -> usize {
        self.upper.as_ref().write_len() + self.lower.write_len()
    }

    unsafe fn write_stage1(&self, mem: NonNull<u8>) {
        let upper = self.upper.as_ref();

        upper.write_stage1(mem);
        self.lower.write_stage1(mem.add(upper.write_len()));
    }

    unsafe fn write_stage2(&self, mem: NonNull<u8>, payload_len: usize) {
        let upper = self.upper.as_ref();

        let uplen = upper.write_len();
        let mem2 = mem.add(uplen);

        upper.write_stage2(mem, payload_len);
        self.lower.write_stage2(mem2, payload_len - uplen);
    }
}

unsafe impl<'a, U: IsSafeToWrite, L: Protocol> IsSafeToWrite for Stacked<'a, U, L> {}

impl<T: IsSafeToWrite + Sized> IntoBoxedBytes for T {
    fn into_boxed_bytes(self) -> Box<[u8]> {
        let total_size = self.write_len();
        let mut data = alloc::vec![0u8; total_size].into_boxed_slice();

        // SAFETY: Memory allocated by [`Vec`] is guaranteed to be non-null.
        let ptr = unsafe { NonNull::new_unchecked(data.as_mut_ptr()) };

        unsafe {
            self.write_stage1(ptr);
            self.write_stage2(ptr, total_size);
        }

        data
    }
}

#[cfg(test)]
mod tests {
    use super::data_link::{Eth, MacAddr};
    use super::network::{Ipv4, Ipv4Addr, Ipv4Type};
    use super::transport::{Tcp, Udp};
    use super::{IntoBoxedBytes, Stacked};

    // #[test]
    // fn ui() {
    //     let t = trybuild::TestCases::new();
    //     t.compile_fail("tests/ui/*.rs");
    // }

    #[test]
    fn udp_stack() {
        const RAW_PACKET: &[u8] = &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 69, 0, 0, 32, 0, 0, 0, 0, 64, 17, 122, 206,
            255, 255, 255, 255, 255, 255, 255, 255, 31, 144, 0, 80, 0, 12, 85, 108, 69, 69, 69, 69,
        ];

        let eth = Eth::new(MacAddr::NULL, MacAddr::NULL, crate::data_link::Type::Ip);
        let ip = Ipv4::new(Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST, Ipv4Type::Udp);
        let udp = Udp::new(8080, 80);

        let packet = (eth / ip / udp / [69u8; 4]).into_boxed_bytes();
        assert_eq!(&*packet, RAW_PACKET);
    }

    #[test]
    fn tcp_stack() {
        const RAW_PACKET: &[u8] = &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 69, 0, 0, 44, 0, 0, 0, 0, 64, 6, 122, 205,
            255, 255, 255, 255, 255, 255, 255, 255, 31, 144, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 80, 0,
            0, 0, 5, 119, 0, 0, 69, 69, 69, 69,
        ];

        let eth = Eth::new(MacAddr::NULL, MacAddr::NULL, crate::data_link::Type::Ip);
        let ip = Ipv4::new(Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST, Ipv4Type::Tcp);
        let tcp = Tcp::new(8080, 80);

        let packet = (eth / ip / tcp / [69u8; 4]).into_boxed_bytes();
        assert_eq!(&*packet, RAW_PACKET);
    }

    #[test]
    fn unsized_payload() {
        const RAW_PACKET: &[u8] = &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 69, 0, 0, 32, 0, 0, 0, 0, 64, 17, 122, 206,
            255, 255, 255, 255, 255, 255, 255, 255, 31, 144, 0, 80, 0, 12, 85, 108, 69, 69, 69, 69,
        ];

        // Payload as a slice.
        let payload: &[u8] = [69u8; 4].as_slice();

        let eth = Eth::new(MacAddr::NULL, MacAddr::NULL, crate::data_link::Type::Ip);
        let ip = Ipv4::new(Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST, Ipv4Type::Udp);
        let udp = Udp::new(8080, 80);

        let packet = (eth / ip / udp / payload).into_boxed_bytes();
        assert_eq!(&*packet, RAW_PACKET);
    }

    #[test]
    fn parsed_packet() {
        let eth = Eth::new(MacAddr::NULL, MacAddr::NULL, crate::data_link::Type::Ip);

        let x = Stacked {
            upper: crate::MaybeOwned::Borrowed(&eth),
            lower: [2, 3, 4],
        };
    }
}
