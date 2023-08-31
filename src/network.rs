use byte_endian::BigEndian;

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
#[repr(transparent)]
pub struct Ipv4Addr(pub [u8; Self::ADDR_SIZE]);

impl Ipv4Addr {
    /// Size of IPv4 adderess in octets.
    ///
    /// [RFC 8200 § 2]: https://www.rfc-editor.org/rfc/rfc791#section-3.2
    pub const ADDR_SIZE: usize = 4;
    pub const BROADCAST: Self = Self([0xff; Self::ADDR_SIZE]);

    pub fn new(addr: [u8; Self::ADDR_SIZE]) -> Self {
        Self(addr)
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum Ipv4Type {
    Tcp = 6u8.swap_bytes(),
    Udp = 17u8.swap_bytes(),
}

crate::make! {
    // 20 bytes wide
    struct Ipv4 {
        v: BigEndian<u8>,
        tos: BigEndian<u8>,
        length: BigEndian<u16>,
        ident: BigEndian<u16>,
        frag_offset: BigEndian<u16>,
        ttl: BigEndian<u8>,
        protocol: Ipv4Type,
        hcrc: BigEndian<u16>,
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr
    }

    @checksum |mut self, size: usize| {
        self.length = (size as u16).into();
        self
    }
}

impl Ipv4 {
    pub fn new(ty: Ipv4Type, src_ip: Ipv4Addr, dest_ip: Ipv4Addr) -> Self {
        Self {
            v: 0x45.into(),
            tos: 0.into(),
            length: u16::MAX.into(),
            ident: 0.into(),
            frag_offset: 0.into(),
            ttl: 64.into(),
            protocol: ty,
            hcrc: 0.into(),
            src_ip,
            dest_ip,
        }
    }
}
