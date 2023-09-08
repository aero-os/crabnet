use bit_field::BitField;
use byte_endian::BigEndian;
use static_assertions::const_assert_eq;

use crate::network::Ipv4;
use crate::{PointerExtension, Protocol, Stack, Stacked, StackingAnchor};

#[repr(C)]
pub struct Udp {
    pub src_port: BigEndian<u16>,
    pub dst_port: BigEndian<u16>,
    pub len: BigEndian<u16>,
    pub crc: BigEndian<u16>,
}

impl Udp {
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port: src_port.into(),
            dst_port: dst_port.into(),
            len: 0.into(),
            crc: 0.into(),
        }
    }
}

const_assert_eq!(core::mem::size_of::<Udp>(), 8);

unsafe impl StackingAnchor<Udp> for Udp {}
unsafe impl<'a, U: Protocol> StackingAnchor<Udp> for Stacked<'a, U, Udp> {}

impl<U: StackingAnchor<Ipv4>> Stack<U> for Udp
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

crate::impl_stack!(@make Udp {
    fn write_stage2(&self, mem: NonNull<u8>, payload_len: usize) {
        use crate::checksum::{self, PseudoHeader};

        let udp = unsafe { mem.cast::<Udp>().as_mut() };
        let ipv4 = unsafe { mem.cast::<Ipv4>().sub(1).as_ref() };
        let pseudo_header = PseudoHeader::new(ipv4);

        udp.len = (payload_len as u16).into();
        udp.crc = checksum::make_combine(&[checksum::calculate(&pseudo_header), checksum::calculate_with_len(udp, payload_len)]);
    }
});

#[repr(C)]
pub struct Tcp {
    pub src_port: BigEndian<u16>,
    pub dest_port: BigEndian<u16>,
    pub seq_nr: BigEndian<u32>,
    pub ack_nr: BigEndian<u32>,
    pub flags: BigEndian<u16>,
    pub window: BigEndian<u16>,
    pub checksum: BigEndian<u16>,
    pub urgent_ptr: BigEndian<u16>,
}

const_assert_eq!(core::mem::size_of::<Tcp>(), 20);

impl Tcp {
    pub fn new(src_port: u16, dest_port: u16) -> Self {
        let mut flags = 0;
        flags.set_bits(12..=15, core::mem::size_of::<Self>() as u16 / 4);

        Self {
            src_port: src_port.into(),
            dest_port: dest_port.into(),
            seq_nr: 0.into(),
            ack_nr: 0.into(),
            flags: flags.into(),
            window: 0.into(),
            checksum: 0.into(),
            urgent_ptr: 0.into(),
        }
    }

    #[inline]
    pub fn sequence_number(&self) -> u32 {
        self.seq_nr.to_native()
    }

    #[inline]
    pub fn set_sequence_number(mut self, value: u32) -> Self {
        self.seq_nr = value.into();
        self
    }

    #[inline]
    pub fn set_window(mut self, value: u16) -> Self {
        self.window = value.into();
        self
    }

    #[inline]
    pub fn flags(&self) -> TcpFlags {
        let raw = self.flags.to_native().get_bits(0..=5);
        TcpFlags::from_bits_truncate(raw)
    }

    #[inline]
    pub fn set_flags(mut self, value: TcpFlags) -> Self {
        let mut flags = self.flags.to_native();
        flags.set_bits(0..=5, value.bits());

        self.flags = flags.into();
        self
    }

    /// Sets the ACK number to `value` and sets the [`TcpFlags::ACK`] flag.
    #[inline]
    pub fn set_ack_number(mut self, value: u32) -> Self {
        self.ack_nr = value.into();

        let mut flags = self.flags();
        flags.insert(TcpFlags::ACK);
        self.set_flags(flags)
    }
}

impl<'a, T: Protocol, U: Protocol> Stacked<'a, Stacked<'a, Stacked<'a, T, Ipv4>, Tcp>, U> {
    pub fn ack_len(&self) -> u32 {
        let tcp = &self.upper.as_ref().lower;
        let ipv4 = &self.upper.as_ref().upper.as_ref().lower;

        let data_len = ipv4.payload_len() as u32;
        let flags = tcp.flags();

        let mut addend = 0;
        if flags.contains(TcpFlags::FIN) | flags.contains(TcpFlags::SYN) {
            addend = 1;
        }

        data_len + addend
    }
}

unsafe impl StackingAnchor<Tcp> for Tcp {}
unsafe impl<'a, U: Protocol> StackingAnchor<Udp> for Stacked<'a, U, Tcp> {}

impl<U: StackingAnchor<Ipv4>> Stack<U> for Tcp
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

crate::impl_stack!(@make Tcp {
    fn write_stage2(&self, mem: NonNull<u8>, payload_len: usize) {
        use crate::checksum::{self, PseudoHeader};

        let tcp = unsafe { mem.cast::<Tcp>().as_mut() };
        let ipv4 = unsafe { mem.cast::<Ipv4>().sub(1).as_ref() };
        let pseudo_header = PseudoHeader::new(ipv4);

        tcp.checksum = checksum::make_combine(&[checksum::calculate(&pseudo_header), checksum::calculate_with_len(tcp, payload_len)]);
    }
});

bitflags::bitflags! {
    pub struct TcpFlags: u16 {
        const FIN = 1 << 0;
        const SYN = 1 << 1;
        const RST = 1 << 2;
        const PSH = 1 << 3;
        const ACK = 1 << 4;
        const URG = 1 << 5;
    }
}
