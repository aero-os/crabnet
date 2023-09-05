#![feature(new_uninit)]

extern crate alloc;

use core::alloc::Layout;
use core::marker::PhantomData;
use core::ops::Div;
use core::ptr::NonNull;

// Generics:
//
// U: Upper
// L: Lower

#[macro_export]
macro_rules! impl_stack {
    (@make $name:ty {
        fn write_stage2(&self, $mem:ident: *mut u8, $payload_len:ident: usize) $code:block
    }) => {
        impl<L: $crate::Stack<$name>> core::ops::Div<L> for $name {
            type Output = L::Output;

            #[inline]
            fn div(self, rhs: L) -> Self::Output {
                rhs.stack(self)
            }
        }

        unsafe impl $crate::Protocol for $name {
            #[inline]
            fn len(&self) -> usize {
                core::mem::size_of::<Self>()
            }

            unsafe fn write_stage1(&self, mem: *mut u8) {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self,
                        mem.cast::<Self>(),
                        core::mem::size_of::<Self>(),
                    );
                }
            }

            unsafe fn write_stage2(&self, $mem: *mut u8, $payload_len: usize) $code
        }
    }
}

pub mod data_link {
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

    unsafe impl crate::StackingAnchor<Eth> for Eth {}
    unsafe impl<Upper: crate::Protocol> crate::StackingAnchor<Eth> for crate::Stacked<Upper, Eth> {}
    impl<Upper: crate::Protocol> crate::Stack<Upper> for Eth {
        type Output = crate::Stacked<Upper, Self>;

        fn stack(self, lhs: Upper) -> Self::Output {
            Self::Output {
                upper: lhs,
                lower: self,
            }
        }
    }

    crate::impl_stack!(@make Eth {
        fn write_stage2(&self, mem: *mut u8, payload_len: usize) {}
    });

    unsafe impl crate::IsSafeToWrite for Eth {}
}

pub mod network {
    use byte_endian::BigEndian;

    #[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
    #[repr(C)]
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

    #[derive(Debug)]
    #[repr(C)]
    pub struct Ipv4 {
        pub v: BigEndian<u8>,
        pub tos: BigEndian<u8>,
        pub length: BigEndian<u16>,
        pub ident: BigEndian<u16>,
        pub frag_offset: BigEndian<u16>,
        pub ttl: BigEndian<u8>,
        pub protocol: Ipv4Type,
        pub hcrc: BigEndian<u16>,
        pub src_ip: Ipv4Addr,
        pub dest_ip: Ipv4Addr,
    }

    impl Ipv4 {
        pub fn new(src_ip: Ipv4Addr, dest_ip: Ipv4Addr, protocol: Ipv4Type) -> Self {
            Self {
                v: 0x45.into(),
                tos: 0.into(),
                length: 0.into(),
                ident: 0.into(),
                frag_offset: 0.into(),
                ttl: 64.into(),
                hcrc: 0.into(),

                protocol,
                src_ip,
                dest_ip,
            }
        }
    }

    unsafe impl crate::StackingAnchor<Ipv4> for Ipv4 {}
    unsafe impl<Upper: crate::Protocol> crate::StackingAnchor<Ipv4> for crate::Stacked<Upper, Ipv4> {}
    impl<Upper: crate::Protocol> crate::Stack<Upper> for Ipv4 {
        type Output = crate::Stacked<Upper, Self>;

        fn stack(self, lhs: Upper) -> Self::Output {
            Self::Output {
                upper: lhs,
                lower: self,
            }
        }
    }

    crate::impl_stack!(@make Ipv4 {
        fn write_stage2(&self, mem: *mut u8, payload_len: usize) {
            use crate::checksum;
            let ipv4 = unsafe { &mut *mem.cast::<Ipv4>() };

            ipv4.length = (payload_len as u16).into();
            ipv4.hcrc = checksum::make(checksum::calculate(ipv4));
        }
    });
}

pub mod transport {
    use byte_endian::BigEndian;
    use static_assertions::const_assert_eq;

    use crate::network::Ipv4;

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

    unsafe impl crate::StackingAnchor<Udp> for Udp {}
    unsafe impl<Upper: crate::Protocol> crate::StackingAnchor<Udp> for crate::Stacked<Upper, Udp> {}
    impl<Upper: crate::StackingAnchor<Ipv4>> crate::Stack<Upper> for Udp {
        type Output = crate::Stacked<Upper, Self>;

        fn stack(self, lhs: Upper) -> Self::Output {
            Self::Output {
                upper: lhs,
                lower: self,
            }
        }
    }

    crate::impl_stack!(@make Udp {
        fn write_stage2(&self, mem: *mut u8, payload_len: usize) {
            use crate::checksum::{self, PseudoHeader};

            let udp = unsafe { &mut *mem.cast::<Udp>() };
            let ipv4 = unsafe { &*mem.cast::<Ipv4>().sub(1) };
            let pseudo_header = PseudoHeader::new(ipv4);

            udp.len = (payload_len as u16).into();
            udp.crc = checksum::make_combine(&[checksum::calculate(&pseudo_header), checksum::calculate_with_len(udp, payload_len)]);
        }
    });
}

pub mod checksum {
    use byte_endian::BigEndian;

    use super::network::{Ipv4, Ipv4Addr, Ipv4Type};

    #[repr(C, packed)]
    pub struct PseudoHeader {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        reserved: u8,
        ty: Ipv4Type,
        size: BigEndian<u16>,
    }

    impl PseudoHeader {
        pub fn new(ip_hdr: &Ipv4) -> PseudoHeader {
            let len = ip_hdr.length;
            PseudoHeader {
                src_ip: ip_hdr.src_ip,
                dst_ip: ip_hdr.dest_ip,
                reserved: 0,
                ty: ip_hdr.protocol,
                size: BigEndian::from(len.to_native() - core::mem::size_of::<Ipv4>() as u16),
            }
        }
    }

    /// Compute the 32-bit internet checksum for `data`.
    fn calculate_checksum(data: &[u8]) -> u32 {
        let bytes = unsafe {
            core::slice::from_raw_parts(
                data.as_ptr() as *const BigEndian<u16>,
                data.len() / core::mem::size_of::<u16>(),
            )
        };

        let mut sum = bytes
            .iter()
            .take(data.len() / 2)
            .map(|byte| byte.to_native() as u32)
            .sum();

        // Add left-over byte, if any.
        if data.len() % 2 == 1 {
            sum += ((*data.last().unwrap()) as u32) << 8;
        }

        sum
    }

    /// Folds the 32-bit sum (`sum`) to 16 bits in the network byte order.
    pub fn make(mut sum: u32) -> BigEndian<u16> {
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        BigEndian::from(!(sum as u16))
    }

    /// Combine several RFC 1071 compliant checksums.
    pub fn make_combine(a: &[u32]) -> BigEndian<u16> {
        make(a.iter().sum())
    }

    /// Compute the internet checksum for `value`.
    pub fn calculate<T: Sized>(value: &T) -> u32 {
        let bytes = unsafe {
            core::slice::from_raw_parts(value as *const _ as *const u8, core::mem::size_of::<T>())
        };
        calculate_checksum(bytes)
    }

    /// Compute the internet checksum for `value` of `size`.
    pub fn calculate_with_len<T: ?Sized>(value: &T, size: usize) -> u32 {
        let bytes = unsafe { core::slice::from_raw_parts(value as *const _ as *const u8, size) };
        calculate_checksum(bytes)
    }
}

unsafe impl<const N: usize, T> crate::StackingAnchor<[T; N]> for [T; N] {}
unsafe impl<const N: usize, T, U: crate::Protocol> crate::StackingAnchor<[T; N]>
    for crate::Stacked<U, [T; N]>
{
}

impl<const N: usize, T, U: crate::Protocol> crate::Stack<U> for [T; N] {
    type Output = crate::Stacked<U, Self>;

    fn stack(self, lhs: U) -> Self::Output {
        Self::Output {
            upper: lhs,
            lower: self,
        }
    }
}

unsafe impl<const N: usize, T> crate::Protocol for [T; N] {
    #[inline]
    fn len(&self) -> usize {
        core::mem::size_of::<Self>()
    }

    unsafe fn write_stage1(&self, mem: *mut u8) {
        unsafe {
            core::ptr::copy_nonoverlapping(self.as_ptr(), mem.cast::<T>(), N);
        }
    }

    unsafe fn write_stage2(&self, _mem: *mut u8, _payload_len: usize) {}
}

pub unsafe trait Protocol {
    /// Returns the write length in bytes.
    fn len(&self) -> usize;
    unsafe fn write_stage1(&self, mem: *mut u8);
    unsafe fn write_stage2(&self, mem: *mut u8, payload_len: usize);
}

unsafe trait StackingAnchor<U: Protocol>: Protocol {}

pub trait Stack<U: Protocol> {
    type Output;

    fn stack(self, lhs: U) -> Self::Output;
}

pub unsafe trait IsSafeToWrite: Protocol {}

pub struct Stacked<U: Protocol, L: Protocol> {
    upper: U,
    lower: L,
}

impl<U: Protocol, L: Protocol, MuchLower: Stack<Stacked<U, L>>> Div<MuchLower> for Stacked<U, L> {
    type Output = MuchLower::Output;

    #[inline]
    fn div(self, rhs: MuchLower) -> Self::Output {
        rhs.stack(self)
    }
}

unsafe impl<U: Protocol, L: Protocol> Protocol for Stacked<U, L> {
    #[inline]
    fn len(&self) -> usize {
        self.upper.len() + self.lower.len()
    }

    unsafe fn write_stage1(&self, mem: *mut u8) {
        self.upper.write_stage1(mem);
        self.lower.write_stage1(mem.add(self.upper.len()));
    }

    unsafe fn write_stage2(&self, mem: *mut u8, payload_len: usize) {
        let uplen = self.upper.len();
        let mem2 = mem.add(uplen);

        self.upper.write_stage2(mem, payload_len);
        self.lower.write_stage2(mem2, payload_len - uplen);
    }
}

unsafe impl<U: IsSafeToWrite, L: Protocol> IsSafeToWrite for Stacked<U, L> {}

pub struct Packet<T: IsSafeToWrite> {
    ptr: NonNull<u8>,
    layout: Layout,

    // XXX: This marker is required for dropck to understand that we logically own a T.
    _marker: PhantomData<T>,
}

impl<T: IsSafeToWrite> Packet<T> {
    /// Creates a new packet.
    ///
    /// ## Panics
    /// This function panics if the total size of the packet exceeds `isize::MAX` after alignment.
    pub fn new(value: T) -> Self {
        const ALIGNMENT: usize = 4096;

        let total_size = value.len();

        // Check that the total size does not exceed the maximum size for the alignment.
        assert!(total_size <= (isize::MAX as usize - (ALIGNMENT - 1)));

        // SAFETY: We have verified that `total_size` is less than `isize::MAX` after alignment
        // and the alignment is non-zero and a power of two.
        let layout = unsafe { Layout::from_size_align_unchecked(total_size, ALIGNMENT) };

        // SAFETY: The layout has a non-zero size and is properly aligned.
        let ptr = unsafe { alloc::alloc::alloc(layout) };
        let Some(ptr) = NonNull::new(ptr) else {
            // Alloction failed, `ptr` is null, call the error handler.
            alloc::alloc::handle_alloc_error(layout);
        };

        unsafe {
            value.write_stage1(ptr.as_ptr());
            value.write_stage2(ptr.as_ptr(), total_size);
        }

        Packet {
            ptr,
            layout,
            _marker: PhantomData,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.layout.size()) }
    }
}

impl<T: IsSafeToWrite> Drop for Packet<T> {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was allocated by the global allocator and the layout is the same
        // as the one used for allocation.
        unsafe {
            alloc::alloc::dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

pub fn main() {
    use data_link::{Eth, MacAddr};
    use network::{Ipv4, Ipv4Addr, Ipv4Type};
    use transport::Udp;

    let eth = Eth::new(MacAddr::NULL, MacAddr::NULL, data_link::Type::Ip);
    let ip = Ipv4::new(Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST, Ipv4Type::Udp);
    let udp = Udp::new(8080, 80);

    let o = eth / ip / udp / [69u8; 4];

    // Should not compiles:
    //
    // 1.
    // let x = Udp::new(8080, 80) / [69u8; 4];
    // let p = Packet::new(x);
    //
    // 2.
    // let x = Udp::new(8080, 80);
    // let p = Packet::new(x);

    let packet = Packet::new(o);
    println!("{:?}", packet.as_bytes());
}
