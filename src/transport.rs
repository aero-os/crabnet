use bit_field::BitField;
use byte_endian::BigEndian;
use static_assertions::const_assert_eq;

use crate::network::Ipv4;
use crate::{PointerExtension, Protocol, Stack, Stacked, StackingAnchor};

#[repr(C, packed)]
pub struct Udp {
    src_port: BigEndian<u16>,
    dst_port: BigEndian<u16>,
    len: BigEndian<u16>,
    crc: BigEndian<u16>,
}

impl Udp {
    crate::impl_stack!(@getter src_port: BigEndian<u16> as u16, dst_port: BigEndian<u16> as u16);

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
unsafe impl<U: Protocol> StackingAnchor<Udp> for Stacked<U, Udp> {}

impl<U: StackingAnchor<Ipv4>> Stack<U> for Udp {
    type Output = Stacked<U, Self>;

    fn stack(self, lhs: U) -> Self::Output {
        Self::Output {
            upper: lhs,
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

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct TcpFlags: u16 {
        const FIN = 1 << 0;
        const SYN = 1 << 1;
        const RST = 1 << 2;
        const PSH = 1 << 3;
        const ACK = 1 << 4;
        const URG = 1 << 5;
    }
}

#[derive(Debug)]
#[repr(C, packed)]
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
    pub fn src_port(&self) -> u16 {
        self.src_port.to_native()
    }

    pub fn dest_port(&self) -> u16 {
        self.dest_port.to_native()
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
    pub fn window(&self) -> u16 {
        self.window.to_native()
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

    #[inline]
    pub fn ack_number(&self) -> u32 {
        self.ack_nr.to_native()
    }

    /// Sets the ACK number to `value`.
    #[inline]
    pub fn set_ack_number(mut self, value: u32) -> Self {
        self.ack_nr = value.into();
        self
    }

    /// Returns the header size in bytes.
    #[inline]
    pub fn header_size(&self) -> u8 {
        // bits 12..=15 specify the header size in 32-bit words.
        let header_size = self.flags.to_native().get_bits(12..=15);
        header_size as u8 * core::mem::size_of::<u32>() as u8
    }

    #[inline]
    pub fn options_size(&self) -> u8 {
        self.header_size() - core::mem::size_of::<Tcp>() as u8
    }
}

unsafe impl StackingAnchor<Tcp> for Tcp {}
unsafe impl<U: Protocol> StackingAnchor<Udp> for Stacked<U, Tcp> {}

impl<U: StackingAnchor<Ipv4>> Stack<U> for Tcp {
    type Output = Stacked<U, Self>;

    fn stack(self, lhs: U) -> Self::Output {
        Self::Output {
            upper: lhs,
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
