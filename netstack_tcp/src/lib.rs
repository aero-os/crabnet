use std::sync::Arc;
use std::time::Duration;

use netstack::network::{Ipv4, Ipv4Addr, Ipv4Type};
use netstack::transport::{Tcp, TcpFlags};

#[derive(Default, Copy, Clone, PartialEq, Eq, Debug)]
pub enum State {
    /// Waiting for a connection request from any remote TCP peer and port.
    #[default]
    Listen,
    /// Waiting for a matching connection request after having sent a connection request
    SynSent,
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
    /// Waiting for a connection termination request from the local user.
    CloseWait,
    /// Waiting for a connection termination request acknowledgment from the remote TCP peer.
    Closing,
    /// Waiting for an acknowledgment of the connection termination request previously sent to the
    /// remote TCP peer (this termination request sent to the remote TCP peer already included an
    /// acknowledgment of the termination request sent from the remote TCP peer).
    LastAck,
    /// Waiting for enough time to pass to be sure the remote TCP peer received the acknowledgment
    /// of its connection termination request and to avoid new connections being impacted by
    /// delayed segments from previous connections.
    TimeWait,
    /// No connection state at all.
    Closed,
}

/// State of the Send Sequence Space (RFC 793 S3.2 F4)
///
/// ```text
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
    pub wl1: u32,
    /// Segment acknowledgment number used for last window update.
    pub wl2: u32,
    /// Initial send sequence number.
    pub iss: u32,
}

/// State of the Receive Sequence Space (RFC 793 S3.2 F5)
///
/// ```text
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

#[derive(Debug)]
pub struct Address {
    pub src_port: u16,
    pub dest_port: u16,
    pub dest_ip: Ipv4Addr,
}

impl Address {
    #[inline]
    pub fn new(src_port: u16, dest_port: u16, dest_ip: Ipv4Addr) -> Self {
        Self {
            src_port,
            dest_port,
            dest_ip,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Error {
    /// Transport endpoint is not connected.
    NotConnected,
    /// No buffer space available.
    NoBufs,
}

pub struct Socket<D: NetworkDevice> {
    state: State,
    recv: RecvSequenceSpace,
    send: SendSequenceSpace,
    recv_queue: Vec<u8>,
    addr: Address,
    pub device: Arc<D>,
}

impl<D: NetworkDevice> Socket<D> {
    pub fn new(device: Arc<D>, address: Address) -> Self {
        Self {
            device,
            recv: RecvSequenceSpace::default(),
            send: SendSequenceSpace::default(),
            state: State::default(),
            recv_queue: Vec::new(),
            addr: address,
        }
    }

    pub fn connect(device: Arc<D>, address: Address) -> Self {
        let mut socket = Self {
            device,
            recv: RecvSequenceSpace::default(),
            send: SendSequenceSpace::default(),
            state: State::default(),
            recv_queue: Vec::new(),
            addr: address,
        };

        // TODO: Actually set to something what we can handle.
        socket.recv.wnd = u16::MAX;
        socket.send_syn();
        socket
    }

    pub fn send_raw(&mut self, seq_number: u32, flags: TcpFlags, payload: &[u8]) {
        let mut next_seq = seq_number.wrapping_add(payload.len() as u32);
        if flags.contains(TcpFlags::SYN) {
            next_seq = next_seq.wrapping_add(1);
        }

        if flags.contains(TcpFlags::FIN) {
            next_seq = next_seq.wrapping_add(1);
        }

        let ip = Ipv4::new(Ipv4Addr::NULL, self.addr.dest_ip, Ipv4Type::Tcp);
        let tcp = Tcp::new(self.addr.src_port, self.addr.dest_port)
            .set_flags(flags)
            .set_window(self.send.wnd)
            .set_sequence_number(seq_number)
            .set_ack_number(self.recv.nxt);

        if wrapping_lt(self.send.nxt, next_seq) {
            self.send.nxt = next_seq;
        }

        let retransmit_duration = Duration::from_millis(100);
        let retransmit_handle = RetransmitHandle::new(seq_number, retransmit_duration);

        self.device.send(ip, tcp, payload, retransmit_handle);
    }

    #[inline]
    pub fn send_with_flags(&mut self, seq_number: u32, flags: TcpFlags) {
        self.send_raw(seq_number, flags, &[])
    }

    /// Send a SYN packet (connection request).
    fn send_syn(&mut self) {
        self.send.wnd = u16::MAX;
        self.send_with_flags(self.send.nxt, TcpFlags::SYN);
        self.state = State::SynSent;
    }

    /// ## Panics
    /// This function panics if the socket is not in the [`State::TimeWait`] state.
    fn do_timewait(&mut self) {
        assert_eq!(self.state, State::TimeWait);

        log::info!("[ TCP ] Closing connection");
        // TODO: Wait for 2MSL. Which is (2 * maximum segment lifetime).
        self.state = State::Closed;
    }

    pub fn close(&mut self) {
        match self.state {
            // connection already closed.
            State::Closed => return,
            // connection is closing.
            State::FinWait1
            | State::FinWait2
            | State::Closing
            | State::LastAck
            | State::TimeWait => return,

            State::Listen | State::SynSent => {
                // The connection has not been established yet, so we can just close it.
                self.state = State::Closed;
            }

            State::SynRecv | State::Established => {
                self.send_with_flags(self.send.nxt, TcpFlags::FIN | TcpFlags::ACK);
                self.state = State::FinWait1;
            }

            State::CloseWait => {
                self.send_with_flags(self.send.nxt, TcpFlags::FIN | TcpFlags::ACK);
                self.state = State::LastAck;
            }
        }
    }

    pub fn send(&mut self, payload: &[u8]) -> Result<usize, Error> {
        match self.state {
            State::Closed => Err(Error::NotConnected),
            State::Listen | State::SynSent | State::SynRecv => Err(Error::NoBufs),

            State::Established | State::CloseWait => {
                self.send_raw(self.send.nxt, TcpFlags::ACK | TcpFlags::PSH, payload);
                Ok(payload.len())
            }

            State::LastAck | State::Closing | State::TimeWait => Ok(0),
            _ => unreachable!(),
        }
    }

    pub fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, Error> {
        match self.state {
            State::Closed => Err(Error::NotConnected),
            State::Listen | State::SynSent | State::SynRecv => Err(Error::NoBufs),

            State::Established | State::CloseWait => {
                let bytes_copy = buffer.len().min(self.recv_queue.len());

                buffer[..bytes_copy].copy_from_slice(&self.recv_queue[..bytes_copy]);
                self.recv_queue.drain(..bytes_copy);

                Ok(bytes_copy)
            }

            State::LastAck | State::Closing | State::TimeWait => Ok(0),
            _ => unreachable!(),
        }
    }

    pub fn on_packet(&mut self, tcp: &Tcp, payload: &[u8]) {
        let flags = tcp.flags();
        let mut acceptable = false;

        // Calculate the segment length.
        let mut slen = payload.len() as u32;

        if flags.contains(TcpFlags::SYN) {
            slen += 1;
        }

        if flags.contains(TcpFlags::FIN) {
            slen += 1;
        }

        match self.state {
            State::Closed => return,

            State::Listen => {
                if flags.contains(TcpFlags::RST) {
                    // Incoming RST should be ignored.
                    return;
                }

                if flags.contains(TcpFlags::ACK) {
                    // Bad ACK; connection is still in the listen state.
                    self.send_with_flags(tcp.ack_number(), TcpFlags::RST);
                    return;
                }

                if !flags.contains(TcpFlags::SYN) {
                    // Expected a SYN packet.
                    return;
                }

                self.state = State::SynRecv;

                // Keep track of the sender info.
                self.recv.irs = tcp.sequence_number();
                self.recv.nxt = tcp.sequence_number().wrapping_add(1);
                self.recv.wnd = tcp.window();

                // Initialize send sequence space.
                self.send.iss = 0;
                self.send.nxt = self.send.iss.wrapping_add(1);
                self.send.una = 0;
                self.send.wnd = u16::MAX;

                // Send SYN-ACK.
                self.send_with_flags(self.send.iss, TcpFlags::SYN | TcpFlags::ACK);
                return;
            }

            State::SynSent => {
                let ack_number = tcp.ack_number();

                if flags.contains(TcpFlags::ACK) {
                    if wrapping_lt(ack_number.wrapping_sub(1), self.send.iss)
                        || wrapping_gt(ack_number, self.send.nxt)
                    {
                        if flags.contains(TcpFlags::RST) {
                            // Drop the segment and return.
                            return;
                        }

                        // Send a reset; drop the segment and return.
                        self.send_with_flags(ack_number, TcpFlags::RST);
                        return;
                    }

                    acceptable = is_between_wrapped(
                        self.send.una.wrapping_sub(1),
                        ack_number,
                        self.send.nxt.wrapping_add(1),
                    );
                }

                if flags.contains(TcpFlags::RST) {
                    if acceptable {
                        log::error!("[ TCP ] Connection Reset");
                        self.state = State::Closed;
                    }

                    // Drop the segment and return.
                    return;
                }

                if flags.contains(TcpFlags::ACK | TcpFlags::SYN) {
                    self.recv.nxt = tcp.sequence_number().wrapping_add(1);
                    self.recv.irs = tcp.sequence_number();

                    if acceptable {
                        self.send.una = tcp.ack_number();
                    }

                    if wrapping_gt(self.send.una, self.send.iss) {
                        // TODO(andypython): Parse TCP options.
                        self.send.wnd = tcp.window();
                        self.send.wl1 = tcp.sequence_number();
                        self.send.wl2 = tcp.ack_number();
                        self.state = State::Established;

                        self.send_with_flags(self.send.nxt, TcpFlags::ACK);
                        return;
                    } else {
                        self.state = State::SynRecv;

                        self.send_with_flags(self.send.iss, TcpFlags::SYN | TcpFlags::ACK);
                        return;
                    }
                } else {
                    // Bad segment; drop and return.
                    return;
                }
            }

            _ => {}
        }

        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let seq_number = tcp.sequence_number();

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
        if (slen == 0)
            && ((self.recv.wnd == 0 && seq_number == self.recv.nxt)
                || is_between_wrapped(self.recv.nxt.wrapping_sub(1), seq_number, wend))
        {
            acceptable = true;
        } else {
            if self.recv.wnd == 0 {
                acceptable = false;
            } else if is_between_wrapped(self.recv.nxt.wrapping_sub(1), seq_number, wend)
                || is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seq_number.wrapping_add(slen - 1),
                    wend,
                )
            {
                acceptable = true;
            }
        };

        if !acceptable {
            if !flags.contains(TcpFlags::RST) {
                self.send_with_flags(self.send.nxt, TcpFlags::ACK);
            }

            return;
        }

        assert!(flags.contains(TcpFlags::ACK));

        match self.state {
            State::SynRecv => {
                if !flags.contains(TcpFlags::ACK) {
                    // Expected an ACK for the sent SYN.
                    return;
                }

                // ACKed the SYN (i.e, at least one acked byte and we have only sent the SYN).
                self.state = State::Established;
            }

            State::Established
            | State::FinWait1
            | State::FinWait2
            | State::CloseWait
            | State::Closing => {
                if is_between_wrapped(
                    self.send.una.wrapping_sub(1),
                    tcp.ack_number(),
                    self.send.nxt.wrapping_add(1),
                ) {
                    self.send.una = tcp.ack_number();
                    // TODO:
                    //     Any segments on the retransmission queue that are thereby entirely
                    //     acknowledged are removed. Users should receive positive acknowledgments
                    //     for buffers that have been SENT and fully acknowledged (i.e., SEND buffer
                    //     should be returned with "ok" response).

                    if wrapping_lt(self.send.wl1, tcp.sequence_number())
                        || (self.send.wl1 == tcp.sequence_number()
                            && wrapping_lt(self.send.wl2.wrapping_sub(1), tcp.ack_number()))
                    {
                        self.send.wnd = tcp.window();
                        self.send.wl1 = tcp.sequence_number();
                        self.send.wl2 = tcp.ack_number();
                    }
                } else if wrapping_gt(tcp.ack_number(), self.send.nxt) {
                    self.send_with_flags(self.send.nxt, TcpFlags::ACK);
                    return;
                }

                if let State::FinWait1 = self.state {
                    if tcp.ack_number() == self.send.nxt {
                        self.state = State::FinWait2;
                    }
                } else if let State::Closing = self.state {
                    todo!()
                }
            }

            State::LastAck => {
                // The only thing that can arrive in this state is an acknowledgment of our FIN. If
                // our FIN is now acknowledged enter [`State::Closed`].
                if tcp.ack_number() == self.send.nxt {
                    self.state = State::Closed;
                    return;
                }
            }

            state => todo!("{state:?}"),
        }

        match self.state {
            State::Established if !payload.is_empty() => {
                let seq_number = tcp.sequence_number();
                if seq_number != self.recv.nxt {
                    log::warn!("[ TCP ] Recieved out of order packet");
                    return;
                }

                // Advance RCV.NXT and adjust RCV.WND as apporopriate to the current buffer
                // availability.
                self.recv.nxt = seq_number.wrapping_add(payload.len() as u32);
                self.recv.wnd = u16::MAX;

                self.recv_queue.extend_from_slice(payload);
                log::debug!("unread_data: {:?}", payload);
                self.send_with_flags(self.send.nxt, TcpFlags::ACK);
            }

            _ => {}
        }

        if flags.contains(TcpFlags::FIN) {
            match self.state {
                State::SynRecv | State::Established => {
                    self.state = State::CloseWait;
                }

                State::FinWait1 => {
                    // Enter [`State::TimeWait`] if our FIN is now acknowledged.
                    if tcp.ack_number() == self.send.nxt {
                        self.state = State::TimeWait;
                        self.do_timewait();
                    } else {
                        self.state = State::Closing;
                    }
                }

                State::FinWait2 => {
                    self.state = State::TimeWait;
                    self.do_timewait();
                }

                State::TimeWait => todo!("restart the 2 MSL time-wait timeout"),

                State::CloseWait | State::Closing | State::LastAck => {}
                state => unimplemented!("<FIN> {state:?}"),
            }

            self.recv.nxt = tcp.sequence_number().wrapping_add(1);
            self.send_with_flags(self.send.nxt, TcpFlags::ACK);
        }
    }

    #[inline]
    pub fn state(&self) -> State {
        self.state.clone()
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
pub const fn wrapping_gt(lhs: u32, rhs: u32) -> bool {
    wrapping_lt(rhs, lhs)
}

#[inline]
pub const fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}

pub struct RetransmitHandle {
    pub seq_number: u32,

    /// The duration to wait before retransmitting the packet.
    pub duration: Duration,
}

impl RetransmitHandle {
    pub fn new(seq_number: u32, duration: Duration) -> Self {
        Self {
            seq_number,
            duration,
        }
    }
}

pub trait NetworkDevice: Send + Sync {
    fn send(&self, ipv4: Ipv4, tcp: Tcp, payload: &[u8], handle: RetransmitHandle);

    /// Removes the retransmit handle from the retransmit queue.
    fn remove_retransmit(&self, seq_number: u32);
}
