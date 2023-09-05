#![feature(new_uninit)]

extern crate alloc;

use core::alloc::Layout;
use core::marker::PhantomData;
use core::ops::Div;
use core::ptr::NonNull;

pub mod checksum;
pub mod data_link;
pub mod network;
pub mod transport;

// Generics:
//
// U: Upper
// L: Lower

#[macro_export]
macro_rules! impl_stack {
    (@make $name:ty {
        fn write_stage2(&self, $mem:ident: *mut u8, $payload_len:ident: usize) $code:block
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
            fn len(&self) -> usize {
                core::mem::size_of::<Self>()
            }

            unsafe fn write_stage1(&self, mem: core::ptr::NonNull<u8>) {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self,
                        mem.as_ptr().cast::<Self>(),
                        core::mem::size_of::<Self>(),
                    );
                }
            }

            unsafe fn write_stage2(&self, $mem: core::ptr::NonNull<u8>, $payload_len: usize) $code
        }
    }
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

unsafe impl<const N: usize, T> StackingAnchor<[T; N]> for [T; N] {}
unsafe impl<const N: usize, T, U: Protocol> crate::StackingAnchor<[T; N]>
    for crate::Stacked<U, [T; N]>
{
}

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
    fn len(&self) -> usize {
        core::mem::size_of::<Self>()
    }

    unsafe fn write_stage1(&self, mem: NonNull<u8>) {
        unsafe {
            core::ptr::copy_nonoverlapping(self.as_ptr(), mem.cast::<T>().as_ptr(), N);
        }
    }

    unsafe fn write_stage2(&self, _mem: NonNull<u8>, _payload_len: usize) {}
}

pub unsafe trait Protocol {
    /// Returns the write length in bytes.
    fn len(&self) -> usize;
    unsafe fn write_stage1(&self, mem: NonNull<u8>);
    unsafe fn write_stage2(&self, mem: NonNull<u8>, payload_len: usize);
}

unsafe trait StackingAnchor<U: Protocol>: Protocol {}

pub trait Stack<U: Protocol> {
    type Output;

    fn stack(self, lhs: U) -> Self::Output;
}

pub unsafe trait IsSafeToWrite: Protocol {}

pub struct Stacked<U: Protocol, L: Protocol> {
    upper: U,
    lower: L,
}

impl<U: Protocol, L: Protocol, MuchLower: Stack<Stacked<U, L>>> Div<MuchLower> for Stacked<U, L> {
    type Output = MuchLower::Output;

    #[inline]
    fn div(self, rhs: MuchLower) -> Self::Output {
        rhs.stack(self)
    }
}

unsafe impl<U: Protocol, L: Protocol> Protocol for Stacked<U, L> {
    #[inline]
    fn len(&self) -> usize {
        self.upper.len() + self.lower.len()
    }

    unsafe fn write_stage1(&self, mem: NonNull<u8>) {
        self.upper.write_stage1(mem);
        self.lower.write_stage1(mem.add(self.upper.len()));
    }

    unsafe fn write_stage2(&self, mem: NonNull<u8>, payload_len: usize) {
        let uplen = self.upper.len();
        let mem2 = mem.add(uplen);

        self.upper.write_stage2(mem, payload_len);
        self.lower.write_stage2(mem2, payload_len - uplen);
    }
}

unsafe impl<U: IsSafeToWrite, L: Protocol> IsSafeToWrite for Stacked<U, L> {}

pub struct Packet<T: IsSafeToWrite> {
    ptr: NonNull<u8>,
    layout: Layout,

    // XXX: This marker is required for dropck to understand that we logically own a T.
    _marker: PhantomData<T>,
}

impl<T: IsSafeToWrite> Packet<T> {
    /// Creates a new packet.
    ///
    /// ## Panics
    /// This function panics if the total size of the packet exceeds `isize::MAX` after alignment.
    pub fn new(value: T) -> Self {
        const ALIGNMENT: usize = 4096;

        let total_size = value.len();

        // Check that the total size does not exceed the maximum size for the alignment.
        assert!(total_size <= (isize::MAX as usize - (ALIGNMENT - 1)));

        // SAFETY: We have verified that `total_size` is less than `isize::MAX` after alignment
        // and the alignment is non-zero and a power of two.
        let layout = unsafe { Layout::from_size_align_unchecked(total_size, ALIGNMENT) };

        // SAFETY: The layout has a non-zero size and is properly aligned.
        let ptr = unsafe { alloc::alloc::alloc(layout) };
        let Some(ptr) = NonNull::new(ptr) else {
            // Alloction failed, `ptr` is null, call the error handler.
            alloc::alloc::handle_alloc_error(layout);
        };

        unsafe {
            value.write_stage1(ptr);
            value.write_stage2(ptr, total_size);
        }

        Packet {
            ptr,
            layout,
            _marker: PhantomData,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.layout.size()) }
    }
}

impl<T: IsSafeToWrite> Drop for Packet<T> {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was allocated by the global allocator and the layout is the same
        // as the one used for allocation.
        unsafe {
            alloc::alloc::dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ui() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/*.rs");
    }
}
