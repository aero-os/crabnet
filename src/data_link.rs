#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
#[repr(transparent)]
pub struct MacAddr(pub [u8; Self::ADDR_SIZE]);

impl MacAddr {
    pub const ADDR_SIZE: usize = 6;
    pub const BROADCAST: Self = Self([0xff; Self::ADDR_SIZE]);
    pub const NULL: Self = Self([0; Self::ADDR_SIZE]);
}

#[derive(Debug)]
#[repr(u16)]
pub enum EthernetType {
    Ip = 0x800u16.swap_bytes(),
    Arp = 0x0806u16.swap_bytes(),
}

crate::make! {
    // 14 bytes wide
    struct Ethernet {
        dest_mac: MacAddr,
        src_mac: MacAddr,
        ty: EthernetType
    }

    @checksum |self, _size: usize| { self }
}

impl Ethernet {
    pub fn new(ty: EthernetType, src_mac: MacAddr, dest_mac: MacAddr) -> Self {
        Self {
            dest_mac,
            src_mac,
            ty,
        }
    }
}
