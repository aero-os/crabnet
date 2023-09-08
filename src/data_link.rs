use crate::{IsSafeToWrite, Protocol, Stack, Stacked, StackingAnchor};

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
#[repr(transparent)]
pub struct MacAddr(pub [u8; Self::ADDR_SIZE]);

impl MacAddr {
    pub const ADDR_SIZE: usize = 6;
    pub const BROADCAST: Self = Self([0xff; Self::ADDR_SIZE]);
    pub const NULL: Self = Self([0; Self::ADDR_SIZE]);
}

#[repr(u16)]
pub enum Type {
    Ip = 0x800u16.swap_bytes(),
    Arp = 0x0806u16.swap_bytes(),
}

#[repr(C)]
pub struct Eth {
    pub dest_mac: MacAddr,
    pub src_mac: MacAddr,
    pub typ: Type,
}

impl Eth {
    pub fn new(dest_mac: MacAddr, src_mac: MacAddr, typ: Type) -> Self {
        Self {
            dest_mac,
            src_mac,
            typ,
        }
    }
}

unsafe impl StackingAnchor<Eth> for Eth {}
unsafe impl<'a, U: Protocol> StackingAnchor<Eth> for Stacked<'a, U, Eth> {}
unsafe impl IsSafeToWrite for Eth {}

impl<U: Protocol> Stack<U> for Eth
where
    U: 'static,
{
    type Output = Stacked<'static, U, Self>;

    fn stack(self, lhs: U) -> Self::Output {
        Self::Output {
            upper: crate::MaybeOwned::Owned(lhs),
            lower: self,
        }
    }
}

crate::impl_stack!(@make Eth {
    fn write_stage2(&self, _mem: NonNull<u8>, _payload_len: usize) {}
});
