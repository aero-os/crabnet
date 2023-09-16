use netstack::data_link::EthType;
use netstack::network::{Ipv4, Ipv4Addr, Ipv4Type};
use netstack::transport::Tcp;
use netstack::{IntoBoxedBytes, PacketParser, Protocol};
use netstack_tcp::{Address, NetworkDevice, RetransmitHandle, Socket as TcpSocket};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tun_tap::{Iface, Mode};

#[used]
#[link_section = ".init_array"]
static INIT_LOGGER: extern "C" fn() -> usize = {
    /// Initializes the global logger with an env logger.
    #[link_section = ".text.startup"]
    extern "C" fn __init_logger() -> usize {
        env_logger::init();
        0
    }

    __init_logger
};

struct RetransmitEntry {
    handle: RetransmitHandle,
    now: Instant,
}

/// <https://www.kernel.org/doc/Documentation/networking/tuntap.txt>
struct Tun {
    iface: Iface,
    queue: Mutex<HashMap<u32, RetransmitEntry>>,
}

impl Tun {
    pub fn new(iface: Iface) -> Arc<Self> {
        use std::thread;

        let s1 = Arc::new(Self {
            iface,
            queue: Mutex::new(HashMap::new()),
        });

        let s2 = s1.clone();

        thread::spawn(move || loop {
            for (key, timer) in s2.queue.lock().unwrap().iter_mut() {
                if Instant::now() - timer.now >= timer.handle.duration {
                    // todo!()
                }
            }
        });

        s1
    }
}

impl NetworkDevice for Tun {
    fn send(&self, mut ipv4: Ipv4, tcp: Tcp, payload: &[u8], handle: RetransmitHandle) {
        use netstack::data_link::Tun;

        self.queue.lock().unwrap().insert(
            handle.seq_number,
            RetransmitEntry {
                handle,
                now: Instant::now(),
            },
        );

        // The IP is set in the run.sh script.
        ipv4.src_ip = Ipv4Addr::new([192, 168, 0, 2]);

        let tun = Tun::new(0, EthType::Ip);
        let packet = (tun / ipv4 / tcp / payload).into_boxed_bytes();

        self.iface
            .send(&packet)
            .expect("tun: failed to send packet");
    }

    fn remove_retransmit(&self, seq_number: u32) {
        self.queue.lock().unwrap().remove(&seq_number);
    }
}

pub fn main() -> io::Result<()> {
    let iface = Iface::new("tun0", Mode::Tun)?;
    let device = Tun::new(iface);

    let mut buf = [0u8; 1504];
    let mut tcp_socket: Option<TcpSocket<Tun>> = None;
    let mut done = false;

    while let Ok(bytes_read) = device.iface.recv(&mut buf) {
        // TODO: Check the first 4 bytes, the TUN header and discard if it's not IPv4.
        let packet = &buf[4..bytes_read];

        let mut packet_parser = PacketParser::new(packet);
        let ipv4 = packet_parser.next::<Ipv4>();

        if ipv4.protocol != Ipv4Type::Tcp {
            continue;
        }

        let tcp = packet_parser.next::<Tcp>();
        let options_size = tcp.header_size() as usize - tcp.write_len();
        let payload = &packet_parser.payload()[options_size..];

        if let Some(tcp_socket) = tcp_socket.as_mut() {
            tcp_socket.on_packet(tcp, payload);

            if tcp_socket.state() == netstack_tcp::State::Established && !done {
                tcp_socket.send(b"okay!").unwrap();
                done = true;
            }
        } else {
            let address = Address::new(tcp.dest_port(), tcp.src_port(), ipv4.src_ip);
            let socket = TcpSocket::new(device.clone(), address);

            tcp_socket = Some(socket);
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use netstack::data_link;
    use netstack_tcp::State;

    use std::ops::{Deref, DerefMut};

    use super::*;

    struct RetransmitEntry {
        handle: RetransmitHandle,
        now: Instant,
        raw: Vec<u8>,
    }

    /// A network packet.
    #[derive(Debug, Clone)]
    struct Packet(Box<[u8]>);

    /// Fake network device.
    struct FakeDevice {
        /// Receive queue of this device.
        this: Arc<Mutex<Vec<Packet>>>,
        /// Receive of the peer device.
        peer: Arc<Mutex<Vec<Packet>>>,
        /// The TCP re-transmit queue.
        queue: Mutex<HashMap<u32, RetransmitEntry>>,
    }

    impl FakeDevice {
        pub fn recv(&self, buf: &mut [u8]) -> Option<usize> {
            let mut this = self.this.lock().unwrap();
            if this.is_empty() {
                return None;
            }

            let packet = this.remove(0);
            let bytes_read = packet.0.len().min(buf.len());
            assert_ne!(bytes_read, 0);

            buf[..bytes_read].copy_from_slice(&packet.0[..bytes_read]);
            Some(bytes_read)
        }
    }

    impl NetworkDevice for FakeDevice {
        fn send(&self, ipv4: Ipv4, tcp: Tcp, payload: &[u8], handle: RetransmitHandle) {
            let tun = data_link::Tun::new(0, EthType::Ip);
            let packet = (tun / ipv4 / tcp / payload).into_boxed_bytes();

            let seq_number = handle.seq_number;
            let rt_entry = RetransmitEntry {
                handle,
                now: Instant::now(),
                raw: packet.clone().into_vec(),
            };

            self.queue.lock().unwrap().insert(seq_number, rt_entry);
            self.peer.lock().unwrap().push(Packet(packet));
        }

        fn remove_retransmit(&self, seq_number: u32) {
            self.queue.lock().unwrap().remove(&seq_number);
        }
    }

    /// Spawns a timer thread for the given device.
    fn spwan_timer(device: Arc<FakeDevice>) {
        use std::thread;
        use std::time::Duration;

        thread::spawn(move || loop {
            let now = Instant::now();

            let mut queue = device.queue.lock().unwrap();
            let mut peer = device.peer.lock().unwrap();

            for timer in queue.values_mut() {
                if now - timer.now >= timer.handle.duration {
                    peer.push(Packet(timer.raw.clone().into_boxed_slice()));
                    timer.handle.duration *= 2;
                }
            }

            drop(peer);
            drop(queue);

            // Check the timers every 100ms.
            thread::sleep(Duration::from_millis(100));
        });
    }

    fn socket_pair() -> (SocketShim, SocketShim) {
        let p1 = Arc::new(Mutex::new(vec![]));
        let p2 = Arc::new(Mutex::new(vec![]));

        let n1 = Arc::new(FakeDevice {
            this: p1.clone(),
            peer: p2.clone(),
            queue: Mutex::new(HashMap::new()),
        });

        let n2 = Arc::new(FakeDevice {
            this: p2.clone(),
            peer: p1.clone(),
            queue: Mutex::new(HashMap::new()),
        });

        spwan_timer(n1.clone());
        spwan_timer(n2.clone());

        let a1 = Address::new(1234, 5678, Ipv4Addr::new([192, 168, 0, 1]));
        let a2 = Address::new(5678, 1234, Ipv4Addr::new([192, 168, 0, 2]));

        (
            SocketShim::new(TcpSocket::new(n1, a1)),
            SocketShim::new(TcpSocket::connect(n2, a2)),
        )
    }

    struct SocketShim(TcpSocket<FakeDevice>);

    impl SocketShim {
        #[inline]
        fn new(socket: TcpSocket<FakeDevice>) -> Self {
            Self(socket)
        }

        fn skip_by(&mut self, packets: usize) {
            for _ in 0..packets {
                self.await_process();
            }
        }

        fn await_process(&mut self) {
            let mut buf = [0u8; 1504];
            let device = &self.0.device;

            loop {
                if let Some(bytes_read) = device.recv(&mut buf) {
                    let mut packet_parser = PacketParser::new(&buf[..bytes_read]);

                    let tun = packet_parser.next::<data_link::Tun>();
                    let x = tun.typ;
                    assert_eq!(x, EthType::Ip);

                    let ipv4 = packet_parser.next::<Ipv4>();
                    assert_eq!(ipv4.protocol, Ipv4Type::Tcp);

                    let tcp = packet_parser.next::<Tcp>();
                    let options_size = tcp.header_size() as usize - tcp.write_len();
                    let payload = &packet_parser.payload()[options_size..];

                    self.0.on_packet(tcp, payload);
                    break;
                }
            }
        }
    }

    impl Deref for SocketShim {
        type Target = TcpSocket<FakeDevice>;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl DerefMut for SocketShim {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    #[test]
    fn normal_connection() {
        let (mut server, mut client) = socket_pair();

        // Normal 3-way handshake.
        assert_eq!(server.state(), State::Listen);
        assert_eq!(client.state(), State::SynSent);

        server.await_process();
        assert_eq!(server.state(), State::SynRecv);

        client.await_process();
        assert_eq!(client.state(), State::Established);

        server.await_process();
        assert_eq!(server.state(), State::Established);

        // Close the connection.
        client.close();
        assert_eq!(client.state(), State::FinWait1);

        server.await_process();
        assert_eq!(server.state(), State::CloseWait);
    }

    #[test]
    fn send_bytes() {
        let (mut server, mut client) = socket_pair();
        server.await_process();
        client.await_process();
        server.await_process();

        // Send some yummy bytes.
        client.send(b"Hello, world!").expect("failed to send bytes");
        server.await_process();

        let mut buf = [0u8; 512];
        let bytes_read = server.recv(&mut buf).expect("failed to recv bytes");
        assert_eq!(bytes_read, 13);
        assert_eq!(&buf[..bytes_read], b"Hello, world!");

        client.close();
        server.await_process();
    }

    #[test]
    fn retransmission() {
        use std::thread;
        use std::time::Duration;

        let (mut server, mut client) = socket_pair();

        // Normal 3-way handshake.
        assert_eq!(server.state(), State::Listen);
        assert_eq!(client.state(), State::SynSent);

        server.await_process();
        assert_eq!(server.state(), State::SynRecv);

        client.await_process();
        assert_eq!(client.state(), State::Established);

        server.await_process();
        assert_eq!(server.state(), State::Established);

        // Close the connection.
        client.close();
        assert_eq!(client.state(), State::FinWait1);

        thread::sleep(Duration::from_millis(100));

        // The client should have atleast re-transmitted once.
        server.skip_by(1);
        server.await_process();
        assert_eq!(server.state(), State::CloseWait);
    }
}
