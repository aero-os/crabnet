use crate::{net_enum, ConstHeader, Packet};

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
#[repr(transparent)]
pub struct MacAddr(pub [u8; Self::ADDR_SIZE]);

impl MacAddr {
    pub const ADDR_SIZE: usize = 6;
    pub const BROADCAST: Self = Self([0xff; Self::ADDR_SIZE]);
    pub const NULL: Self = Self([0; Self::ADDR_SIZE]);
}

net_enum! {
    pub enum EthType(u16) {
        Ip = 0x800,
        Arp = 0x0806
    }
}

#[repr(C)]
pub struct Ethernet {
    pub dest_mac: MacAddr,
    pub src_mac: MacAddr,
    pub ty: EthType,
}

impl Ethernet {
    /// Creates a new ethernet packet with the given payload size (`size`).
    #[inline]
    pub fn new(size: usize) -> Packet<Ethernet> {
        Packet::new(size + Self::HEADER_SIZE)
    }

    /// Sets the protocol to `ty`.
    #[inline]
    pub fn set_protocol(mut self: Packet<Self>, ty: EthType) -> Packet<Self> {
        self.ty = ty;
        self
    }
}

impl ConstHeader for Ethernet {}
