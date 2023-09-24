use bit_field::BitField;
use byte_endian::BigEndian;
use static_assertions::const_assert_eq;

use crate::network::Ipv4;
use crate::{Parsable, Parsed, PointerExtension, Protocol, Stack, Stacked, StackingAnchor};

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
        let mut tcp = Self {
            src_port: src_port.into(),
            dest_port: dest_port.into(),
            seq_nr: 0.into(),
            ack_nr: 0.into(),
            flags: 0.into(),
            window: 0.into(),
            checksum: 0.into(),
            urgent_ptr: 0.into(),
        };

        tcp.set_header_size(core::mem::size_of::<Self>() as u8);
        tcp
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

    /// Sets the header size to `size`.
    ///
    /// # Panics
    /// This function panics if `size` is less than the size of the TCP header.
    #[inline]
    fn set_header_size(&mut self, size: u8) {
        assert!(size >= core::mem::size_of::<Self>() as u8);

        let mut flags = self.flags.to_native();
        flags.set_bits(12..=15, size as u16 / 4);
        self.flags = flags.into();
    }

    #[inline]
    pub fn options_size(&self) -> u8 {
        self.header_size() - core::mem::size_of::<Tcp>() as u8
    }
}

unsafe impl StackingAnchor<Tcp> for Tcp {}
unsafe impl<U: Protocol> StackingAnchor<Tcp> for Stacked<U, Tcp> {}

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

const TCP_OPTEOL: u8 = 0;

const TCP_OPTNOP: u8 = 1;
const TCP_LENNOP: usize = 1;

const TCP_OPTMSS: u8 = 2;
const TCP_LENMSS: usize = 4;

const TCP_OPTWINDOW_SCALE: u8 = 3;
const TCP_LENWINDOW_SCALE: usize = 3;

const TCP_OPTSACKPERM: u8 = 4;
const TCP_LENSACKPERM: usize = 2;

// const TCP_OPTSACK: u8 = 5;
const TCP_OPTTIMESTAMPS: u8 = 8;
const TCP_LENTIMESTAMPS: usize = 10;

#[derive(Debug)]
pub enum TcpOptionErr {
    /// The TCP option had an invalid size.
    InvalidSize,
    /// Unknown TCP option.
    UnknownOption { kind: u8, size: u8 },
}

#[derive(Debug, Clone, PartialEq)]
pub enum TcpOption {
    /// The maximum receive segment size at the TCP endpoint that sends this segment.
    MaxSegmentSize(u16),
    /// The first number is the sender timestamp and the latter is the echo timestamp.
    TimeStamp(u32, u32),
    WindowScale(u8),
    /// Selective ACKs are permitted.
    SackPermitted,
}

pub struct TcpOptionsIter<'a> {
    options: &'a [u8],
    cursor: usize,
}

impl<'a> Iterator for TcpOptionsIter<'a> {
    type Item = Result<TcpOption, TcpOptionErr>;

    fn next(&mut self) -> Option<Self::Item> {
        // FIXME(andypython): In this case, it is an unexpected end of options list (i.e, the
        // EOL option was not found). Should we return an error instead?
        let kind = *self.options.get(self.cursor)?;

        if kind == TCP_OPTEOL {
            // EOL (used for delimiting the options list)
            return None;
        } else if kind == TCP_OPTNOP {
            // NOP (used for padding)
            self.cursor += TCP_LENNOP;
            return self.next();
        }

        let option_size = *self.options.get(self.cursor + 1)?;

        // `expected_size` is the size in bytes of the option with the kind and size fields.
        let mut ensure_size = |expected_size: usize| {
            if (option_size as usize) != expected_size {
                self.cursor += option_size as usize;
                return Err(TcpOptionErr::InvalidSize);
            }

            if (self.cursor + expected_size) > self.options.len() {
                self.cursor += expected_size;
                return Err(TcpOptionErr::InvalidSize);
            }

            let data_start = self.cursor + 2;
            let data_end = self.cursor + expected_size;

            let option = &self.options[data_start..data_end];
            self.cursor += expected_size;
            Ok(option)
        };

        match kind {
            TCP_OPTMSS => match ensure_size(TCP_LENMSS) {
                Ok(data) => {
                    let mss = u16::from_be_bytes([data[0], data[1]]);
                    Some(Ok(TcpOption::MaxSegmentSize(mss)))
                }

                Err(err) => Some(Err(err)),
            },

            TCP_OPTWINDOW_SCALE => match ensure_size(TCP_LENWINDOW_SCALE) {
                Ok(data) => Some(Ok(TcpOption::WindowScale(data[0]))),
                Err(err) => Some(Err(err)),
            },

            TCP_OPTSACKPERM => match ensure_size(TCP_LENSACKPERM) {
                Ok(_) => Some(Ok(TcpOption::SackPermitted)),
                Err(err) => Some(Err(err)),
            },

            TCP_OPTTIMESTAMPS => match ensure_size(TCP_LENTIMESTAMPS) {
                Ok(data) => {
                    let init_ts = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                    let echo_ts = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                    Some(Ok(TcpOption::TimeStamp(init_ts, echo_ts)))
                }

                Err(err) => Some(Err(err)),
            },

            _ => {
                if option_size == 0 {
                    // Invalid option length.
                    Some(Err(TcpOptionErr::InvalidSize))
                } else {
                    // Unknown option, skip it.
                    self.cursor += option_size as usize;

                    Some(Err(TcpOptionErr::UnknownOption {
                        kind,
                        size: option_size,
                    }))
                }
            }
        }
    }
}

pub struct TcpOptionsBuilder {
    // XXX: The maximum size of the TCP options is 40 bytes.
    options: [u8; 40],
    cursor: usize,
}

impl TcpOptionsBuilder {
    pub fn new() -> Self {
        Self {
            options: [0; 40],
            cursor: 0,
        }
    }

    pub fn with(mut self, option: TcpOption) -> Self {
        match option {
            TcpOption::MaxSegmentSize(mss) => {
                self.options[self.cursor] = TCP_OPTMSS;
                self.options[self.cursor + 1] = TCP_LENMSS as u8;
                self.options[self.cursor + 2..self.cursor + TCP_LENMSS]
                    .copy_from_slice(&mss.to_be_bytes());

                self.cursor += TCP_LENMSS;
            }

            TcpOption::WindowScale(scale) => {
                self.options[self.cursor] = TCP_OPTWINDOW_SCALE;
                self.options[self.cursor + 1] = TCP_LENWINDOW_SCALE as u8;
                self.options[self.cursor + 2] = scale;

                self.cursor += TCP_LENWINDOW_SCALE;
            }

            TcpOption::SackPermitted => {
                self.options[self.cursor] = TCP_OPTSACKPERM;
                self.options[self.cursor + 1] = TCP_LENSACKPERM as u8;

                self.cursor += TCP_LENSACKPERM;
            }

            TcpOption::TimeStamp(init_ts, echo_ts) => {
                let init_ts = init_ts.to_be_bytes();
                let echo_ts = echo_ts.to_be_bytes();

                self.options[self.cursor] = TCP_OPTTIMESTAMPS;
                self.options[self.cursor + 1] = TCP_LENTIMESTAMPS as u8;

                self.options[self.cursor + 2..self.cursor + 6].copy_from_slice(&init_ts);
                self.options[self.cursor + 6..self.cursor + 10].copy_from_slice(&echo_ts);

                self.cursor += TCP_LENTIMESTAMPS;
            }
        }

        self
    }

    pub fn build<'a>(&'a mut self) -> TcpOptions<'a> {
        self.options[self.cursor] = TCP_OPTEOL;
        self.cursor += 1;

        TcpOptions(&self.options[..self.cursor])
    }
}

#[derive(Debug)]
pub struct TcpOptions<'a>(&'a [u8]);

impl<'a> TcpOptions<'a> {
    /// Returns the TCP options as a byte slice.
    #[inline]
    pub fn as_slice(&self) -> &'a [u8] {
        self.0
    }

    #[inline]
    pub fn iter(&self) -> TcpOptionsIter<'a> {
        TcpOptionsIter {
            options: self.0,
            cursor: 0,
        }
    }
}

impl<'a> From<&'a [u8]> for TcpOptions<'a> {
    #[inline]
    fn from(value: &'a [u8]) -> Self {
        Self(value)
    }
}

unsafe impl<'a> Parsable<'a> for TcpOptions<'a> {
    type Output = TcpOptions<'a>;

    fn parse<'b>(mem: *const u8, size: usize) -> crate::Parsed<TcpOptions<'a>> {
        let header_size = core::mem::size_of::<Tcp>();

        // SAFETY: We only implement Stack<Tcp, TcpOptions> for [`TcpOptions`] and we do not
        // implement [`IsSafeToWrite`], so we know that the the parent layer is TCP thus, the
        // pointer dereference is valid.
        let tcp = unsafe { &*(mem.sub(header_size) as *const Tcp) };
        let options_size = tcp.options_size() as usize;

        // TODO: Invalid header, return an error.
        assert!(options_size <= size);

        let options = unsafe { core::slice::from_raw_parts(mem, options_size) };

        Parsed {
            value: TcpOptions(options),
            size: options_size,
        }
    }
}

unsafe impl<'a> StackingAnchor<TcpOptions<'a>> for TcpOptions<'a> {}
unsafe impl<'a, U: Protocol> StackingAnchor<TcpOptions<'a>> for Stacked<U, TcpOptions<'a>> {}

impl<'a, U: StackingAnchor<Tcp>> Stack<U> for TcpOptions<'a> {
    type Output = Stacked<U, Self>;

    #[inline]
    fn stack(self, lhs: U) -> Self::Output {
        Self::Output {
            upper: lhs,
            lower: self,
        }
    }
}

impl<'a, L: Stack<TcpOptions<'a>>> core::ops::Div<L> for TcpOptions<'a> {
    type Output = L::Output;

    #[inline]
    fn div(self, rhs: L) -> Self::Output {
        rhs.stack(self)
    }
}

unsafe impl<'a> Protocol for TcpOptions<'a> {
    #[inline]
    fn write_len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    unsafe fn write_stage1(&self, mem: core::ptr::NonNull<u8>) {
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.0.as_ptr(),
                mem.as_ptr().cast::<u8>(),
                self.0.len(),
            );
        }

        let header_size = core::mem::size_of::<Tcp>();

        // SAFETY: We only implement Stack<Tcp, TcpOptions> for [`TcpOptions`] and we do not
        // implement [`IsSafeToWrite`], so we know that the the parent layer is TCP. In addition,
        // the caller must guarantee that we have exclusive access to the whole packet thus, the
        // pointer dereference is valid.
        let tcp = unsafe { mem.sub(header_size).cast::<Tcp>().as_mut() };
        tcp.set_header_size(self.0.len() as u8 + header_size as u8);
    }

    #[inline]
    unsafe fn write_stage2(&self, _mem: core::ptr::NonNull<u8>, _payload_len: usize) {}
}
