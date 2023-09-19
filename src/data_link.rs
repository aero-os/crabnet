use byte_endian::BigEndian;
use static_assertions::const_assert_eq;

use crate::network::Ipv4Addr;
use crate::{IsSafeToWrite, Protocol, Stack, Stacked, StackingAnchor};

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
#[repr(transparent)]
pub struct MacAddr(pub [u8; Self::ADDR_SIZE]);

impl MacAddr {
    pub const ADDR_SIZE: usize = 6;
    pub const BROADCAST: Self = Self([0xff; Self::ADDR_SIZE]);
    pub const NULL: Self = Self([0; Self::ADDR_SIZE]);
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u16)]
pub enum EthType {
    Ip = 0x800u16.swap_bytes(),
    Arp = 0x0806u16.swap_bytes(),
}

// Eth
#[repr(C, packed)]
pub struct Eth {
    pub dest_mac: MacAddr,
    pub src_mac: MacAddr,
    typ: EthType,
}

const_assert_eq!(core::mem::size_of::<Eth>(), 14);

impl Eth {
    crate::impl_stack!(@getter dest_mac: MacAddr as MacAddr, src_mac: MacAddr as MacAddr, typ: EthType as EthType);

    pub fn new(dest_mac: MacAddr, src_mac: MacAddr, typ: EthType) -> Self {
        Self {
            dest_mac,
            src_mac,
            typ,
        }
    }
}

unsafe impl StackingAnchor<Eth> for Eth {}
unsafe impl<U: Protocol> StackingAnchor<Eth> for Stacked<U, Eth> {}
unsafe impl IsSafeToWrite for Eth {}

impl<U: Protocol> Stack<U> for Eth {
    type Output = Stacked<U, Self>;

    fn stack(self, lhs: U) -> Self::Output {
        Self::Output {
            upper: lhs,
            lower: self,
        }
    }
}

crate::impl_stack!(@make Eth {
    fn write_stage2(&self, _mem: NonNull<u8>, _payload_len: usize) {}
});

// Tun
#[repr(C, packed)]
pub struct Tun {
    pub flags: BigEndian<u16>,
    pub typ: EthType,
}

const_assert_eq!(core::mem::size_of::<Tun>(), 4);

impl Tun {
    pub fn new(flags: u16, typ: EthType) -> Self {
        Self {
            flags: flags.into(),
            typ,
        }
    }
}

unsafe impl StackingAnchor<Tun> for Tun {}
unsafe impl<U: Protocol> StackingAnchor<Tun> for Stacked<U, Eth> {}
unsafe impl IsSafeToWrite for Tun {}

impl<U: Protocol> Stack<U> for Tun {
    type Output = Stacked<U, Self>;

    fn stack(self, lhs: U) -> Self::Output {
        Self::Output {
            upper: lhs,
            lower: self,
        }
    }
}

crate::impl_stack!(@make Tun {
    fn write_stage2(&self, _mem: NonNull<u8>, _payload_len: usize) {}
});

// ARP
#[derive(Debug, PartialEq)]
pub struct ArpAddress(MacAddr, Ipv4Addr);

impl ArpAddress {
    pub fn new(mac: MacAddr, ip: Ipv4Addr) -> Self {
        Self(mac, ip)
    }

    pub fn mac(&self) -> MacAddr {
        self.0
    }

    pub fn ip(&self) -> Ipv4Addr {
        self.1
    }
}

/// ARP Hardware Type
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum ArpHardwareType {
    Ethernet = 1u16.swap_bytes(),
}

/// ARP Opcode
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub enum ArpOpcode {
    Request = 1u16.swap_bytes(),
    Reply = 2u16.swap_bytes(),
}

#[repr(C, packed)]
pub struct Arp {
    pub htype: ArpHardwareType,
    pub ptype: EthType,
    /// Length in octets of a hardware address.
    pub hlen: BigEndian<u8>,
    /// Length in octets of an internetwork address.
    pub plen: BigEndian<u8>,
    pub opcode: ArpOpcode,
    pub src_mac: MacAddr,
    pub src_ip: Ipv4Addr,
    pub dest_mac: MacAddr,
    pub dest_ip: Ipv4Addr,
}

const_assert_eq!(core::mem::size_of::<Arp>(), 28);

impl Arp {
    /// Creates a new ARP header,
    pub fn new(
        htype: ArpHardwareType,
        ptype: EthType,
        src: ArpAddress,
        dest: ArpAddress,
        opcode: ArpOpcode,
    ) -> Self {
        Self {
            htype,
            ptype,
            hlen: BigEndian::new(MacAddr::ADDR_SIZE as u8),
            plen: BigEndian::new(Ipv4Addr::ADDR_SIZE as u8),
            opcode,
            src_mac: src.mac(),
            src_ip: src.ip(),
            dest_mac: dest.mac(),
            dest_ip: dest.ip(),
        }
    }
}

unsafe impl StackingAnchor<Arp> for Arp {}
unsafe impl<U: Protocol> StackingAnchor<Arp> for Stacked<U, Arp> {}
unsafe impl IsSafeToWrite for Arp {}

impl<U: Protocol> Stack<U> for Arp {
    type Output = Stacked<U, Self>;

    fn stack(self, lhs: U) -> Self::Output {
        Self::Output {
            upper: lhs,
            lower: self,
        }
    }
}

crate::impl_stack!(@make Arp {
    fn write_stage2(&self, _mem: NonNull<u8>, _payload_len: usize) {}
});
