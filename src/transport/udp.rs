use byte_endian::BigEndian;
use static_assertions::const_assert_eq;

use crate::network::Ipv4;
use crate::{Parsable, Protocol, Stack, Stacked, StackingAnchor};

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
