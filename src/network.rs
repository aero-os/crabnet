use crate::data_link::{EthType, Ethernet};
use crate::{checksum, ConstHeader, Packet, PacketUpHierarchy};

use super::net_enum;

use byte_endian::BigEndian;
use static_assertions::const_assert_eq;

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
#[repr(transparent)]
pub struct Ipv4Addr(pub [u8; Self::ADDR_SIZE]);

impl Ipv4Addr {
    /// Size of IPv4 adderess in octets.
    ///
    /// [RFC 8200 § 2]: https://www.rfc-editor.org/rfc/rfc791#section-3.2
    pub const ADDR_SIZE: usize = 4;
    pub const BROADCAST: Self = Self([0xff; Self::ADDR_SIZE]);

    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self([a, b, c, d])
    }
}

net_enum! {
    pub enum Ipv4Type(u8) {
        Tcp = 6,
        Udp = 17
    }
}

#[repr(C)]
pub struct Ipv4 {
    /// Version number of the Internet Protocol.
    version: BigEndian<u8>,
    pub tos: BigEndian<u8>,
    /// Size of entire IP packet in bytes.
    length: BigEndian<u16>,
    pub ident: BigEndian<u16>,
    pub frag_offset: BigEndian<u16>,
    pub ttl: BigEndian<u8>,
    pub protocol: Ipv4Type,
    /// IPv4 Header Checksum.
    pub(crate) hcrc: BigEndian<u16>,
    pub src_ip: Ipv4Addr,
    pub dest_ip: Ipv4Addr,
}

const_assert_eq!(core::mem::size_of::<Ipv4>(), 20);

impl Ipv4 {
    /// Creates a new IPv4 packet with the given payload size (`size`).
    pub fn new(size: usize) -> Packet<Ipv4> {
        let size = size + Self::HEADER_SIZE;
        let ethernet = Ethernet::new(size).set_protocol(EthType::Ip);

        let mut ipv4 = ethernet.upgrade();

        ipv4.version = 0x45u8.into();
        ipv4.tos = 0.into();
        ipv4.ident = 0.into();
        ipv4.frag_offset = 0.into();
        ipv4.ttl = 64.into();
        ipv4.length = (size as u16).into();

        ipv4
    }

    /// Returns the size of the IPv4 packet in bytes, including the header and the payload.
    #[inline]
    pub fn length(&self) -> u16 {
        self.length.to_native()
    }

    /// Sets the source IP address to `target`.
    #[inline]
    pub fn set_src(mut self: Packet<Self>, target: Ipv4Addr) -> Packet<Self> {
        self.src_ip = target;
        self
    }

    /// Sets the destination IP address to `target`.
    #[inline]
    pub fn set_dest(mut self: Packet<Self>, target: Ipv4Addr) -> Packet<Self> {
        self.dest_ip = target;
        self
    }

    /// Sets the protocol to `protocol`.
    #[inline]
    pub fn set_protocol(mut self: Packet<Self>, protocol: Ipv4Type) -> Packet<Self> {
        self.protocol = protocol;
        self
    }

    /// Calculates and fills in the checksum field of the IPv4 header.
    #[inline]
    pub fn compute_checksum(mut self: Packet<Self>) -> Packet<Self> {
        self.hcrc = checksum::make(checksum::calculate(self.header()));
        self
    }
}

impl ConstHeader for Ipv4 {}
impl PacketUpHierarchy<Ipv4> for Packet<Ethernet> {
    fn can_upgrade(&self) -> bool {
        self.ty == EthType::Ip
    }
}
