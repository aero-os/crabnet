use byte_endian::BigEndian;

crate::make! {
    // 8 bytes wide
    struct Udp {
        src_port: BigEndian<u16>,
        dst_port: BigEndian<u16>,
        length: BigEndian<u16>,
        crc: BigEndian<u16>
    }

    @checksum |mut self, size: usize| {
        self.length = (size as u16).into();
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
