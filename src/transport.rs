//! Transport Layer (OSI layer 4).

use byte_endian::BigEndian;
use static_assertions::const_assert_eq;

use crate::checksum::{self, PseudoHeader};
use crate::network::{Ipv4, Ipv4Addr, Ipv4Type};
use crate::{ConstHeader, Packet, PacketDownHierarchy, PacketUpHierarchy};

#[repr(C)]
pub struct Udp {
    pub(crate) src_port: BigEndian<u16>,
    pub(crate) dst_port: BigEndian<u16>,
    pub(crate) length: BigEndian<u16>,
    pub(crate) crc: BigEndian<u16>,
}

const_assert_eq!(core::mem::size_of::<Udp>(), 8);

impl Udp {
    /// Creates a new UDP packet with the given payload size (`size`).
    pub fn new(size: usize) -> Packet<Udp> {
        let size = size + Self::HEADER_SIZE;
        let ipv4 = Ipv4::new(size).set_protocol(Ipv4Type::Udp);

        let mut udp = ipv4.upgrade();

        udp.src_port = 0.into();
        udp.dst_port = 0.into();
        udp.length = BigEndian::from(size as u16);
        udp.crc = 0.into();

        udp
    }

    /// Returns the size of the UDP packet in bytes.
    #[inline]
    pub fn length(&self) -> u16 {
        self.length.to_native()
    }

    /// Sets the source IP and port to `ip` and `port`.
    #[inline]
    pub fn set_src(mut self: Packet<Self>, ip: Ipv4Addr, port: u16) -> Packet<Self> {
        self.src_port = port.into();

        let ipv4 = self.downgrade();
        ipv4.set_src(ip).upgrade()
    }

    /// Sets the destination IP and port to `ip` and `port`.
    #[inline]
    pub fn set_dest(mut self: Packet<Self>, ip: Ipv4Addr, port: u16) -> Packet<Self> {
        self.dst_port = port.into();

        let ipv4 = self.downgrade();
        ipv4.set_dest(ip).upgrade()
    }

    #[inline]
    pub fn compute_checksum(self: Packet<Self>) -> Packet<Self> {
        let ipv4 = self.downgrade().compute_checksum();
        let pseudo_header = PseudoHeader::new(&ipv4);

        let mut udp = ipv4.upgrade();
        udp.crc = checksum::make_combine(&[
            checksum::calculate(&pseudo_header),
            checksum::calculate_with_len(udp.header(), udp.length() as usize),
        ]);

        udp
    }
}

impl ConstHeader for Udp {}
impl PacketUpHierarchy<Udp> for Packet<Ipv4> {
    fn can_upgrade(&self) -> bool {
        self.protocol == Ipv4Type::Udp
    }
}
