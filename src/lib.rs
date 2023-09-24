#![no_std]
#![feature(allocator_api, trivial_bounds, new_uninit, associated_type_defaults)]

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

        unsafe impl<'a> Parsable<'a> for $name {
            type Output = &'a Self;

            fn parse(mem: *const u8, size: usize) -> crate::Parsed<Self::Output> {
                let protocol_size = core::mem::size_of::<Self>();
                assert!(size >= protocol_size);

                let header = unsafe { &*(mem.cast::<Self>()) };

                crate::Parsed {
                    value: header,
                    size: protocol_size
                }
            }
        }
    };

    (@getter $($field_name:ident: $type:ty as $casted:ty),*) => {
        $(
            pub fn $field_name(&self) -> $casted {
                self.$field_name.into()
            }
        )*
    }
}

pub trait IntoBoxedBytes
where
    Self: Sized,
{
    fn into_boxed_bytes(self) -> Box<[u8]> {
        self.into_boxed_bytes_in(Global)
    }

    fn into_boxed_bytes_in<A: Allocator>(self, alloc: A) -> Box<[u8], A>;
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
unsafe impl<const N: usize, T, U: Protocol> StackingAnchor<[T; N]> for crate::Stacked<U, [T; N]> {}

impl<const N: usize, T, U: Protocol> Stack<U> for [T; N] {
    type Output = Stacked<U, Self>;

    fn stack(self, lhs: U) -> Self::Output {
        Self::Output {
            upper: lhs,
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
unsafe impl<T, U: Protocol> StackingAnchor<&[T]> for crate::Stacked<U, &[T]> {}

impl<T, U: Protocol> Stack<U> for &[T] {
    type Output = Stacked<U, Self>;

    fn stack(self, lhs: U) -> Self::Output {
        Self::Output {
            upper: lhs,
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

pub unsafe trait StackingAnchor<U: Protocol>: Protocol {}

pub trait Stack<U: Protocol> {
    type Output;

    fn stack(self, lhs: U) -> Self::Output;
}

pub unsafe trait IsSafeToWrite: Protocol {}

pub struct Stacked<U: Protocol, L: Protocol> {
    pub upper: U,
    pub lower: L,
}

impl<U: Protocol, L: Protocol, K: Stack<Stacked<U, L>>> Div<K> for Stacked<U, L> {
    type Output = K::Output;

    #[inline]
    fn div(self, rhs: K) -> Self::Output {
        rhs.stack(self)
    }
}

unsafe impl<U: Protocol, L: Protocol> Protocol for Stacked<U, L> {
    #[inline]
    fn write_len(&self) -> usize {
        self.upper.write_len() + self.lower.write_len()
    }

    unsafe fn write_stage1(&self, mem: NonNull<u8>) {
        self.upper.write_stage1(mem);
        self.lower.write_stage1(mem.add(self.upper.write_len()));
    }

    unsafe fn write_stage2(&self, mem: NonNull<u8>, payload_len: usize) {
        let uplen = self.upper.write_len();
        let mem2 = mem.add(uplen);

        self.upper.write_stage2(mem, payload_len);
        self.lower.write_stage2(mem2, payload_len - uplen);
    }
}

unsafe impl<U: IsSafeToWrite, L: Protocol> IsSafeToWrite for Stacked<U, L> {}

impl<T: IsSafeToWrite + Sized> IntoBoxedBytes for T {
    fn into_boxed_bytes_in<A: Allocator>(self, alloc: A) -> Box<[u8], A> {
        let total_size = self.write_len();
        let mut data = Box::new_uninit_slice_in(total_size, alloc);

        // SAFETY: Memory allocated by [`Vec`] is guaranteed to be non-null.
        let ptr = unsafe { NonNull::new_unchecked(data.as_mut_ptr().cast()) };

        unsafe {
            self.write_stage1(ptr);
            self.write_stage2(ptr, total_size);
        }

        // SAFETY: The data has been initialized above.
        unsafe { data.assume_init() }
    }
}

pub struct Parsed<T> {
    /// The parsed protocol header.
    value: T,
    /// The size of the parsed protocol header.
    size: usize,
}

pub unsafe trait Parsable<'a> {
    type Output;

    fn parse(mem: *const u8, size: usize) -> Parsed<Self::Output>
    where
        Self::Output: 'a;
}

// TODO(andypython): The packet parser API can be further improved.
pub struct PacketParser<'a> {
    payload: &'a [u8],
    cursor: usize,
}

impl<'a> PacketParser<'a> {
    pub fn new(packet: &'a [u8]) -> Self {
        Self {
            payload: packet,
            cursor: 0,
        }
    }

    pub fn next<U>(&mut self) -> <U as Parsable<'a>>::Output
    where
        U: Protocol + StackingAnchor<U> + Parsable<'a> + 'a,
    {
        let mem = &self.payload[self.cursor..];
        let parsed = U::parse(mem.as_ptr(), mem.len());
        self.cursor += parsed.size;
        parsed.value
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.payload[self.cursor..]
    }
}

#[cfg(test)]
pub mod tests {
    use alloc::vec::Vec;

    use crate::transport::{TcpOption, TcpOptions};

    use super::data_link::{Eth, EthType, MacAddr};
    use super::network::{Ipv4, Ipv4Addr, Ipv4Type};
    use super::transport::{Tcp, Udp};
    use super::{IntoBoxedBytes, PacketParser};

    #[test]
    fn ui() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/*.rs");
    }

    #[test]
    fn udp_stack() {
        const RAW_PACKET: &[u8] = &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 69, 0, 0, 32, 0, 0, 0, 0, 64, 17, 122, 206,
            255, 255, 255, 255, 255, 255, 255, 255, 31, 144, 0, 80, 0, 12, 85, 108, 69, 69, 69, 69,
        ];

        let eth = Eth::new(MacAddr::NULL, MacAddr::NULL, EthType::Ip);
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

        let eth = Eth::new(MacAddr::NULL, MacAddr::NULL, EthType::Ip);
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

        let eth = Eth::new(MacAddr::NULL, MacAddr::NULL, EthType::Ip);
        let ip = Ipv4::new(Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST, Ipv4Type::Udp);
        let udp = Udp::new(8080, 80);

        let packet = (eth / ip / udp / payload).into_boxed_bytes();
        assert_eq!(&*packet, RAW_PACKET);
    }

    #[test]
    fn packet_parse() {
        const RAW_PACKET: &[u8] = &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 69, 0, 0, 32, 0, 0, 0, 0, 64, 17, 122, 206,
            255, 255, 255, 255, 255, 255, 255, 255, 31, 144, 0, 80, 0, 12, 85, 108, 69, 69, 69, 69,
        ];

        let mut packet_parser = PacketParser::new(&RAW_PACKET);
        let eth = packet_parser.next::<Eth>();
        assert_eq!(eth.src_mac(), MacAddr::NULL);
        assert_eq!(eth.dest_mac(), MacAddr::NULL);
        assert_eq!(eth.typ(), EthType::Ip);

        let ip = packet_parser.next::<Ipv4>();
        assert_eq!(ip.src_ip(), Ipv4Addr::BROADCAST);
        assert_eq!(ip.dest_ip(), Ipv4Addr::BROADCAST);
        assert_eq!(ip.protocol(), Ipv4Type::Udp);

        let udp = packet_parser.next::<Udp>();
        assert_eq!(udp.src_port(), 8080);
        assert_eq!(udp.dst_port(), 80);
    }

    #[test]
    fn tcp_options_parse() {
        const RAW_PACKET: &[u8] = &[
            69, 0, 0, 60, 118, 48, 64, 0, 64, 6, 67, 56, 192, 168, 0, 1, 192, 168, 0, 2, 168, 138,
            1, 187, 89, 35, 252, 120, 0, 0, 0, 0, 160, 2, 250, 240, 254, 76, 0, 0, 2, 4, 5, 180, 4,
            2, 8, 10, 151, 174, 53, 222, 0, 0, 0, 0, 1, 3, 3, 7,
        ];

        let mut packet_parser = PacketParser::new(&RAW_PACKET);
        let _ip = packet_parser.next::<Ipv4>();
        let _tcp = packet_parser.next::<Tcp>();
        let options = packet_parser.next::<TcpOptions>();

        assert_eq!(
            options.as_slice(),
            &[2, 4, 5, 180, 4, 2, 8, 10, 151, 174, 53, 222, 0, 0, 0, 0, 1, 3, 3, 7]
        );

        let options = options.iter().map(|x| x.unwrap()).collect::<Vec<_>>();

        assert_eq!(
            options.as_slice(),
            &[
                TcpOption::MaxSegmentSize(1460),
                TcpOption::SackPermitted,
                TcpOption::TimeStamp(2544776670, 0),
                TcpOption::WindowScale(7)
            ]
        );
    }
}
