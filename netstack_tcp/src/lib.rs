use std::sync::Arc;

use netstack::network::{Ipv4, Ipv4Type};
use netstack::transport::{Tcp, TcpFlags};

macro_rules! warn_on {
    ($condition:expr, $($fmt:tt)*) => {
        if $condition {
            log::warn!("check `{}` failed with {}", stringify!($condition), $($fmt)*);
            return;
        }
    };
}

#[derive(Default, PartialEq, Eq, Debug)]
pub enum State {
    /// No connection state at all.
    Closed,
    /// Waiting for a connection request from any remote TCP peer and port.
    #[default]
    Listen,
    /// Waiting for a confirming connection request acknowledgment after having both received and
    /// sent a connection request.
    SynRecv,
    /// Open connection, data received can be delivered to the user. The normal state for the data
    /// transfer phase of the connection.
    Established,
    /// Waiting for a connection termination request from the remote TCP peer, or an acknowledgment
    /// of the connection termination request previously sent.
    FinWait1,
    /// Waiting for a connection termination request from the remote TCP peer.
    FinWait2,
}

/// State of the Send Sequence Space (RFC 793 S3.2 F4)
///
/// ```
///            1         2          3          4
///       ----------|----------|----------|----------
///              SND.UNA    SND.NXT    SND.UNA
///                                   +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
#[derive(Default, Debug)]
pub struct SendSequenceSpace {
    /// Send unacknowledged.
    pub una: u32,
    /// Send next.
    pub nxt: u32,
    /// Send window.
    pub wnd: u16,
    /// Send urgent pointer.
    pub up: bool,
    /// Segment sequence number used for last window update.
    pub wl1: usize,
    /// Segment acknowledgment number used for last window update.
    pub wl2: usize,
    /// Initial send sequence number.
    pub iss: u32,
}

/// State of the Receive Sequence Space (RFC 793 S3.2 F5)
///
/// ```
///                1          2          3
///            ----------|----------|----------
///                   RCV.NXT    RCV.NXT
///                             +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
#[derive(Default, Debug)]
pub struct RecvSequenceSpace {
    /// Receive next.
    pub nxt: u32,
    /// Receive window.
    pub wnd: u16,
    /// Receive urgent pointer.
    pub up: bool,
    /// Initial receive sequence number.
    pub irs: u32,
}

pub struct Socket {
    state: State,
    recv: RecvSequenceSpace,
    send: SendSequenceSpace,
    device: Arc<dyn NetworkDevice>,
}

impl Socket {
    pub fn new(device: Arc<dyn NetworkDevice>) -> Self {
        Self {
            device,
            recv: RecvSequenceSpace::default(),
            send: SendSequenceSpace::default(),
            state: State::default(),
        }
    }

    fn send_with_flags(&mut self, ipv4: &Ipv4, tcp: &Tcp, seq_number: u32, flags: TcpFlags) {
        let mut next_seq = seq_number;
        if flags.contains(TcpFlags::SYN) {
            next_seq = next_seq.wrapping_add(1);
        }

        if flags.contains(TcpFlags::FIN) {
            next_seq = next_seq.wrapping_add(1);
        }

        let ip = Ipv4::new(ipv4.dest_ip, ipv4.src_ip, Ipv4Type::Tcp);
        let tcp = Tcp::new(tcp.dest_port(), tcp.src_port())
            .set_flags(flags)
            .set_window(self.send.wnd)
            .set_sequence_number(seq_number)
            .set_ack_number(self.recv.nxt);

        if wrapping_lt(self.send.nxt, next_seq) {
            self.send.nxt = seq_number;
        }

        self.device.send(ip, tcp);
    }

    pub fn recv(&mut self, ipv4: &Ipv4, tcp: &Tcp, payload: &[u8]) {
        warn_on!(!self.validate_packet(tcp, payload), "invalid packet");

        let flags = tcp.flags();

        match self.state {
            State::Closed => return,

            State::Listen => {
                if !flags.contains(TcpFlags::SYN) {
                    // Expected a SYN packet.
                    return;
                }

                warn_on!(!payload.is_empty(), "unexpected payload in SYN packet");

                self.state = State::SynRecv;

                // Keep track of the sender info.
                self.recv.irs = tcp.sequence_number();
                self.recv.nxt = tcp.sequence_number() + 1;
                self.recv.wnd = tcp.window();

                // Initialize send sequence space.
                self.send.iss = 0;
                self.send.nxt = self.send.iss + 1;
                self.send.una = 0;
                self.send.wnd = u16::MAX;

                // Send SYN-ACK.
                self.send_with_flags(ipv4, tcp, self.send.iss, TcpFlags::SYN | TcpFlags::ACK);
            }

            State::SynRecv => {
                if !flags.contains(TcpFlags::ACK) {
                    // Expected an ACK for the sent SYN.
                    return;
                }

                // ACKed the SYN (i.e, at least one acked byte and we have only sent the SYN).
                self.state = State::Established;
            }

            State::Established => {
                let seq_number = tcp.sequence_number();
                if seq_number != self.recv.nxt {
                    log::warn!("[ TCP ] Recieved out of order packet");
                    return;
                }

                // Advance RCV.NXT and adjust RCV.WND as apporopriate to the current buffer
                // availability.
                self.recv.nxt = seq_number.wrapping_add(payload.len() as u32);
                self.recv.wnd = u16::MAX;

                log::debug!("unread_data: {:?}", payload);
                self.send_with_flags(ipv4, tcp, self.send.nxt, TcpFlags::ACK);
            }

            _ => {}
        }
    }

    fn validate_packet(&self, tcp: &Tcp, payload: &[u8]) -> bool {
        let flags = tcp.flags();

        if let State::Closed | State::Listen = self.state {
            return true;
        }

        let ack_number = tcp.ack_number();
        let seq_number = tcp.sequence_number();

        let mut slen = payload.len() as u32;

        if flags.contains(TcpFlags::SYN) {
            slen += 1;
        }

        if flags.contains(TcpFlags::FIN) {
            slen += 1;
        }

        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);

        // Valid segment check.
        //
        // ```text
        // Length  Window
        // ------- -------  -------------------------------------------
        //
        //    0       0     SEG.SEQ = RCV.NXT
        //
        //    0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        //
        //   >0       0     not acceptable
        //
        //   >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        //               or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        // ```
        if slen == 0 {
            if self.recv.wnd == 0 && seq_number != self.recv.nxt {
                return false;
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seq_number, wend) {
                return false;
            }
        } else {
            if self.recv.wnd == 0 {
                return false;
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seq_number, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seq_number.wrapping_add(slen - 1),
                    wend,
                )
            {
                return false;
            }
        };

        // Acceptable ACK check.
        //      SND.UNA =< SEG.ACK =< SND.NXT
        if !is_between_wrapped(
            self.send.una.wrapping_sub(1),
            ack_number,
            self.send.nxt.wrapping_add(1),
        ) {
            return false;
        }

        true
    }
}

#[inline]
pub const fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // From RFC 1323:
    //     TCP determines if a data segment is "old" or "new" by testing
    //     whether its sequence number is within 2**31 bytes of the left edge
    //     of the window, and if it is not, discarding the data as "old".  To
    //     insure that new data is never mistakenly considered old and vice-
    //     versa, the left edge of the sender's window has to be at most
    //     2**31 away from the right edge of the receiver's window.
    lhs.wrapping_sub(rhs) > 2 ^ 31
}

#[inline]
pub const fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}

pub trait NetworkDevice: Send + Sync {
    fn send(&self, ipv4: Ipv4, tcp: Tcp);
}
