use core::fmt;

use byte_endian::BigEndian;
use static_assertions::const_assert_eq;

use crate::{IsSafeToWrite, Parsable, Protocol, Stack, Stacked, StackingAnchor};

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
#[repr(C)]
pub struct Ipv4Addr(pub [u8; Self::ADDR_SIZE]);

impl Ipv4Addr {
    /// Size of IPv4 adderess in octets.
    ///
    /// [RFC 8200 § 2]: https://www.rfc-editor.org/rfc/rfc791#section-3.2
    pub const ADDR_SIZE: usize = 4;
    /// Broadcast address.
    pub const BROADCAST: Self = Self([0xff; Self::ADDR_SIZE]);
    /// Loopback address.
    pub const LOOPBACK: Self = Self([127, 0, 0, 1]);
    // FIXME(andypython): [`Ipv4Addr::NULL`] should not really be used anywhere except for testing.
    // Consider removing it to avoid misuse/confusion.
    pub const NULL: Self = Self([0; Self::ADDR_SIZE]);

    pub fn new(addr: [u8; Self::ADDR_SIZE]) -> Self {
        Self(addr)
    }
}

impl From<[u8; Ipv4Addr::ADDR_SIZE]> for Ipv4Addr {
    fn from(value: [u8; Ipv4Addr::ADDR_SIZE]) -> Self {
        Self(value)
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])?;
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum Ipv4Type {
    Tcp = 6u8.swap_bytes(),
    Udp = 17u8.swap_bytes(),
}

#[derive(Debug)]
#[repr(C, packed)]
pub struct Ipv4 {
    pub v: BigEndian<u8>,
    pub tos: BigEndian<u8>,
    pub(crate) length: BigEndian<u16>,
    pub ident: BigEndian<u16>,
    pub frag_offset: BigEndian<u16>,
    pub ttl: BigEndian<u8>,
    protocol: Ipv4Type,
    checksum: BigEndian<u16>,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
}

const_assert_eq!(core::mem::size_of::<Ipv4>(), 20);

impl Ipv4 {
    crate::impl_stack!(@getter src_ip: Ipv4Addr as Ipv4Addr, dest_ip: Ipv4Addr as Ipv4Addr, protocol: Ipv4Type as Ipv4Type);

    pub fn new(src_ip: Ipv4Addr, dest_ip: Ipv4Addr, protocol: Ipv4Type) -> Self {
        Self {
            v: 0x45.into(),
            tos: 0.into(),
            length: 0.into(),
            ident: 0.into(),
            frag_offset: 0.into(),
            ttl: 64.into(),
            checksum: 0.into(),

            protocol,
            src_ip,
            dest_ip,
        }
    }

    pub fn set_src_ip(mut self, src_ip: Ipv4Addr) -> Self {
        self.src_ip = src_ip;
        self
    }

    #[inline]
    pub fn payload_len(&self) -> u16 {
        let total_length: u16 = self.length.into();
        total_length - (core::mem::size_of::<Self>() as u16)
    }
}

unsafe impl StackingAnchor<Ipv4> for Ipv4 {}
unsafe impl IsSafeToWrite for Ipv4 {}
unsafe impl<U: Protocol> StackingAnchor<Ipv4> for Stacked<U, Ipv4> {}

impl<U: Protocol> Stack<U> for Ipv4 {
    type Output = Stacked<U, Self>;

    fn stack(self, lhs: U) -> Self::Output {
        Self::Output {
            upper: lhs,
            lower: self,
        }
    }
}

crate::impl_stack!(@make Ipv4 {
    fn write_stage2(&self, mem: NonNull<u8>, payload_len: usize) {
        use crate::checksum;
        let ipv4 = unsafe { mem.cast::<Ipv4>().as_mut() };

        ipv4.length = (payload_len as u16).into();
        ipv4.checksum = checksum::make(checksum::calculate(ipv4));
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    use alloc::string::ToString;

    #[test]
    fn ipv4_addr_fmt() {
        assert_eq!(Ipv4Addr::new([127, 0, 0, 1]).to_string(), "127.0.0.1");
    }
}
