use byte_endian::BigEndian;

use crate::checksum::{self, PseudoHeader};

crate::make! {
    // 8 bytes wide
    struct Udp {
        src_port: BigEndian<u16>,
        dst_port: BigEndian<u16>,
        length: BigEndian<u16>,
        crc: BigEndian<u16>
    }

    @checksum |mut self, size: usize| {
        self.length = ((core::mem::size_of::<Udp>() + size) as u16).into();
        self
    }
}

impl Udp {
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port: src_port.into(),
            dst_port: dst_port.into(),
            length: 0.into(),
            crc: 0.into(),
        }
    }
}

impl crate::StackableWith<crate::network::Ipv4> for Udp {
    fn correct_checksum_with(mut self, size: usize, rhs: &crate::network::Ipv4) -> Self {
        self.length = ((core::mem::size_of::<Udp>() + size) as u16).into();
        self.crc = 0.into();

        let header: &Udp = &self;
        let size = header.length.to_native() as usize;
        let pseudo_header = PseudoHeader::new(rhs);

        self.crc = checksum::make_combine(&[
            checksum::calculate(&pseudo_header),
            checksum::calculate_with_len(header, size),
        ]);

        self
    }
}
