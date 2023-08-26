#![warn(clippy::pedantic)]
#![feature(arbitrary_self_types)]

extern crate alloc;

use alloc::alloc::Layout;

use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

pub mod checksum;
pub mod data_link;
pub mod network;
pub mod transport;

#[macro_export]
macro_rules! net_enum {
    ($vis:vis enum $name:ident($repr:ident) { $($field:ident = $value:expr),+ }) => {
        #[derive(Debug, Copy, Clone, PartialEq)]
        #[repr($repr)]
        $vis enum $name {
            $($field = $repr::to_be($value)),*
        }
    };
}

pub trait IsPacket: Sized {}

pub trait PacketHierarchy: Sized {
    /// Returns a pointer to the data-link layer (OSI layer 2).
    fn data_ptr(&self) -> NonNull<u8>;

    /// Returns the layout of the data-link layer (OSI layer 2).
    fn data_layout(&self) -> Layout;

    /// Returns a pointer to the raw packet.
    fn ptr(&self) -> NonNull<u8>;

    /// Returns the size of the packet in bytes.
    fn size(&self) -> usize;
}

pub trait Header: PacketHierarchy {
    /// Returns the size of the header in bytes.
    fn header_size(&self) -> usize;
}

pub trait ConstHeader: IsPacket {
    /// The size of the header in bytes.
    const HEADER_SIZE: usize = core::mem::size_of::<Self>();
}

impl<T: ConstHeader> IsPacket for T {}
impl<T: ConstHeader> Header for Packet<T> {
    fn header_size(&self) -> usize {
        T::HEADER_SIZE
    }
}

pub struct Packet<T: IsPacket> {
    /// Pointer to the base packet.
    base_ptr: NonNull<T>,
    /// Layout of the base packet.
    base_layout: Layout,

    self_ptr: NonNull<T>,
    self_size: usize,

    // XXX: This marker is required for dropck to understand that we logically own a T.
    _marker: PhantomData<T>,
}

impl<T: IsPacket> Packet<T> {
    /// Constructs a new packet with the given payload size (`size`).
    ///
    /// ## Panics
    /// This function panics if the total size of the packet exceeds `isize::MAX` after alignment.
    pub fn new(size: usize) -> Packet<T>
    where
        T: ConstHeader,
    {
        const ALIGNMENT: usize = 4096;

        let total_size = T::HEADER_SIZE + size;

        // Check that the total size does not exceed the maximum size for the alignment.
        assert!(size <= (isize::MAX as usize - (ALIGNMENT - 1)));

        // SAFETY: We have verified that `total_size` is less than `isize::MAX` and the alignment is
        // non-zero and a power of two.
        let layout = unsafe { Layout::from_size_align_unchecked(total_size, ALIGNMENT) };
        let size = layout.size();

        // SAFETY: The layout has a non-zero size and is properly aligned.
        let ptr = unsafe { alloc::alloc::alloc(layout) }.cast::<T>();
        let Some(ptr) = NonNull::new(ptr) else {
            // Alloction failed, `ptr` is null, call the error handler.
            alloc::alloc::handle_alloc_error(layout);
        };

        Packet {
            base_ptr: ptr,
            base_layout: layout,
            self_ptr: ptr,
            self_size: size,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub fn header(&self) -> &T {
        self
    }
}

impl<T: IsPacket> Deref for Packet<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        unsafe { self.self_ptr.as_ref() }
    }
}

impl<T: IsPacket> DerefMut for Packet<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.self_ptr.as_mut() }
    }
}

impl<T: IsPacket> PacketHierarchy for Packet<T> {
    #[inline]
    fn data_ptr(&self) -> NonNull<u8> {
        self.base_ptr.cast()
    }

    #[inline]
    fn data_layout(&self) -> Layout {
        self.base_layout
    }

    #[inline]
    fn ptr(&self) -> NonNull<u8> {
        self.self_ptr.cast()
    }

    #[inline]
    fn size(&self) -> usize {
        self.self_size
    }
}

pub trait PacketUpHierarchy<P: IsPacket>: Header {
    /// Returns whether the packet can be safely upgraded to `P`.
    fn can_upgrade(&self) -> bool;

    fn upgrade(self) -> Packet<P> {
        let header_size = self.header_size();

        let self_ptr = unsafe { self.ptr().as_ptr().add(header_size) };
        let self_size = self.size() - header_size;

        assert!(self.can_upgrade() && self_size >= self.header_size());

        Packet {
            base_ptr: self.data_ptr().cast(),
            base_layout: self.data_layout(),
            self_ptr: unsafe { NonNull::new_unchecked(self_ptr.cast()) },
            self_size,
            _marker: PhantomData,
        }
    }
}

pub trait PacketDownHierarchy<P: ConstHeader>: PacketHierarchy {
    fn downgrade(self) -> Packet<P> {
        let header_size = P::HEADER_SIZE;

        let self_ptr = unsafe { self.ptr().as_ptr().sub(header_size) };
        let self_size = self.size() + header_size;

        Packet {
            base_ptr: self.data_ptr().cast(),
            base_layout: self.data_layout(),
            self_ptr: unsafe { NonNull::new_unchecked(self_ptr.cast()) },
            self_size,
            _marker: PhantomData,
        }
    }
}

impl<'a, T, P> PacketDownHierarchy<P> for Packet<T>
where
    T: ConstHeader,
    P: ConstHeader,
    Packet<P>: PacketUpHierarchy<T> + 'a,
{
}

#[cfg(test)]
mod tests {
    use crate::network::Ipv4Addr;
    use crate::transport::Udp;

    use super::*;

    #[test]
    fn network_hierarchy() {
        let dest_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dest_port = 80;

        let src_ip = Ipv4Addr::new(192, 168, 1, 2);
        let src_port = 12345;

        let udp = Udp::new(0)
            .set_dest(dest_ip, dest_port)
            .set_src(src_ip, src_port)
            .compute_checksum();

        assert_eq!(udp.crc.to_native(), 0x4c01);

        // Calling `compute_checksum` on the UDP packet should also update the checksum of
        // the IPv4 packet.
        let ip = udp.downgrade();
        assert_eq!(ip.hcrc.to_native(), 0xf77d);
    }

    #[test]
    fn net_enum_repr() {
        net_enum! {
            enum Test(u16) {
                X = 0xfe
            }
        }

        if cfg!(target_endian = "big") {
            assert_eq!(Test::X as u16, 0xfe);
        } else {
            assert_eq!(Test::X as u16, 0xfe00);
        }
    }
}
