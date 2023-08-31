// #![no_std]

pub mod data_link;
pub mod network;
pub mod transport;

extern crate alloc;

use core::alloc::Layout;
use core::marker::PhantomData;
use core::ptr::NonNull;

#[macro_export]
macro_rules! make {
    (
        struct $name:ident { $($field_name:ident : $ty:ty),* }

        $($rest:tt)*
    ) => {
        #[repr(C)]
        pub struct $name {
            $(pub $field_name: $ty),*
        }

        impl<U: $crate::Stackable> core::ops::Shl<U> for $name {
            type Output = $crate::Stacked<Self, U>;

            #[inline]
            fn shl(self, rhs: U) -> Self::Output {
                dbg!("a");
                use $crate::Stackable;
                $crate::Stacked::<Self, U>(self.correct_checksum(rhs.write_len()), rhs)
            }
        }

        $crate::make!($($rest)* for $name;);
    };

    (@checksum |$self:ident| $checksum:block for $name:ident;) => {
        impl $crate::Stackable for $name {
            #[inline]
            fn correct_checksum($self, _size: usize) -> Self {
                $checksum
            }

            fn write_len(&self) -> usize {
                core::mem::size_of::<Self>()
            }
        }
    };

    (@checksum |mut $self:ident, $size:ident: usize| $checksum:block for $name:ident;) => {
        impl $crate::Stackable for $name {
            #[inline]
            fn correct_checksum(mut $self, $size: usize) -> Self {
                $checksum
            }

            fn write_len(&self) -> usize {
                core::mem::size_of::<Self>()
            }
        }
    };

    () => {}
}

make! {
    struct Udp {
        x: u8
    }

    @checksum |self| { self }
}

pub trait Stackable {
    fn correct_checksum(self, size: usize) -> Self;
    fn write_len(&self) -> usize;
}

#[repr(C)]
pub struct Stacked<T: Stackable, U: Stackable>(T, U);

impl<T: Stackable, U: Stackable> Stackable for Stacked<T, U> {
    fn correct_checksum(self, size: usize) -> Self {
        let rhs = self.1.write_len();

        Stacked(
            self.0.correct_checksum(rhs + size),
            self.1.correct_checksum(size),
        )
    }

    fn write_len(&self) -> usize {
        self.0.write_len() + self.1.write_len()
    }
}

// T: Current
// U: Next
// R: Next of U
impl<T: Stackable, U: Stackable, R: Stackable> core::ops::Shl<R> for Stacked<T, U> {
    // Stacked<Stacked<T, U>, R>
    type Output = Stacked<Self, R>;

    #[inline]
    fn shl(self, rhs: R) -> Self::Output {
        // :: Stacked<Stacked<Eth, Ip>, Udp>
        //                              ^^^ RHS or `rhs`
        //            ^^^^^^^^^^^^^^^^ LHS or `self`
        //
        // U.write_len() += R.write_len()
        // T.write_len() += R.write_len()
        let rhs_len = rhs.write_len();
        Stacked::<Self, R>(self.correct_checksum(rhs_len), rhs)
    }
}

impl<const N: usize, T> Stackable for [T; N] {
    #[inline]
    fn correct_checksum(self, size: usize) -> Self {
        assert_eq!(size, 0);
        self
    }

    fn write_len(&self) -> usize {
        core::mem::size_of::<Self>()
    }
}

pub struct Packet<T: Stackable> {
    ptr: NonNull<T>,
    layout: Layout,

    _marker: PhantomData<T>,
}

impl<T: Stackable> Packet<T> {
    /// Constructs a new packet.
    ///
    /// ## Panics
    /// This function panics if the size of the packet exceeds `isize::MAX` after alignment.
    pub fn new(value: T) -> Self {
        const ALIGNMENT: usize = 4096;

        let size = core::mem::size_of::<T>();

        // Check that the size does not exceed the maximum size for the alignment.
        assert!(size <= (isize::MAX as usize - (ALIGNMENT - 1)));

        // SAFETY: We have verified that `size` is less than `isize::MAX` and the alignment is
        // non-zero and a power of two.
        let layout = unsafe { Layout::from_size_align_unchecked(size, ALIGNMENT) };

        // SAFETY: The layout has a non-zero size and is properly aligned.
        let ptr = unsafe { alloc::alloc::alloc(layout) }.cast::<T>();
        let Some(mut ptr) = NonNull::new(ptr) else {
            // Alloction failed, `ptr` is null, call the error handler.
            alloc::alloc::handle_alloc_error(layout);
        };

        unsafe {
            *ptr.as_mut() = value;
        }

        Self {
            ptr,
            layout,

            _marker: PhantomData,
        }
    }
}

impl<T: Stackable> core::ops::Deref for Packet<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.ptr.as_ref() }
    }
}

impl<T: Stackable> core::ops::DerefMut for Packet<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.ptr.as_mut() }
    }
}

impl<T: Stackable> Drop for Packet<T> {
    fn drop(&mut self) {
        let ptr = self.ptr.as_ptr();
        unsafe { alloc::alloc::dealloc(ptr.cast(), self.layout) }
    }
}

#[cfg(test)]
mod test {
    use super::data_link::{Ethernet, EthernetType, MacAddr};
    use super::network::{Ipv4, Ipv4Addr, Ipv4Type};
    use super::transport::Udp;
    use super::Packet;

    #[test]
    fn it_works() {
        let eth = Ethernet::new(EthernetType::Ip, MacAddr::NULL, MacAddr::NULL);
        let ip = Ipv4::new(Ipv4Type::Udp, Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST);
        let udp = Udp::new(8080, 80);

        let packet = Packet::new(eth << ip << udp << [0u8; 8]);

        // Ipv4:
        assert_eq!(packet.0 .0 .1.length.to_native(), 16);
        // Udp:
        assert_eq!(packet.0 .1.length.to_native(), 8);
    }
}
