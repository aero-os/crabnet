use core::{cmp, ops};

use bit_field::BitField;
use byte_endian::BigEndian;
use static_assertions::const_assert_eq;

use crate::network::Ipv4;
use crate::{Parsable, Parsed, Protocol, Stack, Stacked, StackingAnchor};

#[derive(Default, Debug, Copy, Clone, PartialEq)]
#[repr(transparent)]
pub struct SeqNumber(u32);

impl From<SeqNumber> for u32 {
    #[inline]
    fn from(item: SeqNumber) -> u32 {
        item.0
    }
}

impl From<u32> for SeqNumber {
    #[inline]
    fn from(item: u32) -> Self {
        Self(item)
    }
}

// Arithmetic operations for [`SeqNumber`].
impl ops::Add<SeqNumber> for SeqNumber {
    type Output = SeqNumber;

    #[inline]
    fn add(self, other: SeqNumber) -> SeqNumber {
        (self.0.wrapping_add(other.0)).into()
    }
}

impl ops::Add<u32> for SeqNumber {
    type Output = SeqNumber;

    #[inline]
    fn add(self, other: u32) -> SeqNumber {
        self + SeqNumber::from(other)
    }
}

impl ops::Sub<SeqNumber> for SeqNumber {
    type Output = SeqNumber;

    #[inline]
    fn sub(self, other: SeqNumber) -> SeqNumber {
        (self.0.wrapping_sub(other.0)).into()
    }
}

impl ops::Sub<u32> for SeqNumber {
    type Output = SeqNumber;

    #[inline]
    fn sub(self, other: u32) -> SeqNumber {
        self - SeqNumber::from(other)
    }
}

impl cmp::PartialOrd for SeqNumber {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        (self.0.wrapping_sub(other.0) as i32).partial_cmp(&0)
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct TcpFlags: u16 {
        /// No more data from sender.
        const FIN = 1 << 0;
        /// Synchronize sequence numbers.
        const SYN = 1 << 1;
        /// Reset the connection.
        const RST = 1 << 2;
        /// Push Function.
        const PSH = 1 << 3;
        /// Acknowledgment field is significant.
        const ACK = 1 << 4;
        /// Urgent pointer field is significant.
        const URG = 1 << 5;
        /// ECN-Echo.
        const ECE = 1 << 6;
        /// Congestion Window Reduced.
        const CWR = 1 << 7;
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
    pub fn sequence_number(&self) -> SeqNumber {
        SeqNumber::from(self.seq_nr.to_native())
    }

    #[inline]
    pub fn set_sequence_number(mut self, value: SeqNumber) -> Self {
        let value: u32 = value.into();

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
    pub fn ack_number(&self) -> SeqNumber {
        SeqNumber::from(self.ack_nr.to_native())
    }

    /// Sets the ACK number to `value`.
    #[inline]
    pub fn set_ack_number(mut self, value: SeqNumber) -> Self {
        let value: u32 = value.into();

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
const TCP_LENEOL: usize = 1;

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

#[derive(Debug)]
pub struct TcpOptions {
    options: [u8; 40],
    size: usize,
}

impl TcpOptions {
    /// Returns the TCP options as a byte slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.options[..self.size]
    }

    #[inline]
    pub fn iter(&self) -> TcpOptionsIter {
        TcpOptionsIter {
            options: self.as_slice(),
            cursor: 0,
        }
    }

    pub fn new() -> Self {
        Self {
            options: [0; 40],
            size: 0,
        }
    }

    pub fn with(mut self, option: TcpOption) -> Self {
        match option {
            TcpOption::MaxSegmentSize(mss) => {
                self.options[self.size] = TCP_OPTMSS;
                self.options[self.size + 1] = TCP_LENMSS as u8;
                self.options[self.size + 2..self.size + TCP_LENMSS]
                    .copy_from_slice(&mss.to_be_bytes());

                self.size += TCP_LENMSS;
            }

            TcpOption::WindowScale(scale) => {
                self.options[self.size] = TCP_OPTWINDOW_SCALE;
                self.options[self.size + 1] = TCP_LENWINDOW_SCALE as u8;
                self.options[self.size + 2] = scale;

                self.size += TCP_LENWINDOW_SCALE;
            }

            TcpOption::SackPermitted => {
                self.options[self.size] = TCP_OPTSACKPERM;
                self.options[self.size + 1] = TCP_LENSACKPERM as u8;

                self.size += TCP_LENSACKPERM;
            }

            TcpOption::TimeStamp(init_ts, echo_ts) => {
                let init_ts = init_ts.to_be_bytes();
                let echo_ts = echo_ts.to_be_bytes();

                self.options[self.size] = TCP_OPTTIMESTAMPS;
                self.options[self.size + 1] = TCP_LENTIMESTAMPS as u8;

                self.options[self.size + 2..self.size + 6].copy_from_slice(&init_ts);
                self.options[self.size + 6..self.size + 10].copy_from_slice(&echo_ts);

                self.size += TCP_LENTIMESTAMPS;
            }
        }

        self
    }
}

unsafe impl Parsable<'_> for TcpOptions {
    type Output = TcpOptions;

    fn parse<'b>(mem: *const u8, size: usize) -> crate::Parsed<TcpOptions> {
        let header_size = core::mem::size_of::<Tcp>();

        // SAFETY: We only implement Stack<Tcp, TcpOptions> for [`TcpOptions`] and we do not
        // implement [`IsSafeToWrite`], so we know that the the parent layer is TCP thus, the
        // pointer dereference is valid.
        let tcp = unsafe { &*(mem.sub(header_size) as *const Tcp) };
        let options_size = tcp.options_size() as usize;

        // TODO: Invalid header, return an error.
        assert!(options_size <= size && options_size <= 40);

        let mut options = [0; 40];

        unsafe {
            core::ptr::copy_nonoverlapping(mem, options.as_mut_ptr(), options_size);
        }

        Parsed {
            value: TcpOptions {
                options,
                size: options_size,
            },
            size: options_size,
        }
    }
}

unsafe impl StackingAnchor<TcpOptions> for TcpOptions {}
unsafe impl<U: Protocol> StackingAnchor<TcpOptions> for Stacked<U, TcpOptions> {}

impl<U: StackingAnchor<Tcp>> Stack<U> for TcpOptions {
    type Output = Stacked<U, Self>;

    #[inline]
    fn stack(self, lhs: U) -> Self::Output {
        Self::Output {
            upper: lhs,
            lower: self,
        }
    }
}

impl<L: Stack<TcpOptions>> core::ops::Div<L> for TcpOptions {
    type Output = L::Output;

    #[inline]
    fn div(self, rhs: L) -> Self::Output {
        rhs.stack(self)
    }
}

unsafe impl Protocol for TcpOptions {
    #[inline]
    fn write_len(&self) -> usize {
        if self.size == 0 {
            // No TCP options.
            0
        } else {
            self.size + TCP_LENEOL
        }
    }

    #[inline]
    unsafe fn write_stage1(&self, mem: core::ptr::NonNull<u8>) {
        if self.size == 0 {
            // No TCP options.
            return;
        }

        let options_size = self.write_len();

        unsafe {
            core::ptr::copy_nonoverlapping(self.options.as_ptr(), mem.as_ptr(), options_size);
        }

        let header_size = core::mem::size_of::<Tcp>();

        // SAFETY: We only implement Stack<Tcp, TcpOptions> for [`TcpOptions`] and we do not
        // implement [`IsSafeToWrite`], so we know that the the parent layer is TCP. In addition,
        // the caller must guarantee that we have exclusive access to the whole packet thus, the
        // pointer dereference is valid.
        let tcp = unsafe { mem.sub(header_size).cast::<Tcp>().as_mut() };
        tcp.set_header_size(options_size as u8 + header_size as u8);
    }

    #[inline]
    unsafe fn write_stage2(&self, _mem: core::ptr::NonNull<u8>, _payload_len: usize) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_seq_nr() {
        let x = SeqNumber::from(0);
        let y = SeqNumber::from(1);
        let z = SeqNumber::from(u32::MAX);

        let wrapped = z + y;
        assert_ne!(x, z);
        assert_eq!(wrapped, x);

        let middle = SeqNumber::from(2u32.pow(31));

        let current = SeqNumber::from(0);
        let next = current + 1;

        assert!(current < next);
        assert!(current < current + middle);
        assert!(current > next + middle);

        let current = SeqNumber::from(u32::MAX);
        let next = current + 1;

        assert!(current < next);
        assert!(current < current + middle);
        assert!(current > next + middle);
    }
}
