use netstack::data_link::EthType;
use netstack::network::{Ipv4, Ipv4Addr, Ipv4Type};
use netstack::transport::Tcp;
use netstack::{IntoBoxedBytes, PacketParser, Protocol};
use netstack_tcp::{Address, NetworkDevice, Socket as TcpSocket};
use std::io;
use std::sync::Arc;
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

/// <https://www.kernel.org/doc/Documentation/networking/tuntap.txt>
struct Tun(Iface);

impl NetworkDevice for Tun {
    fn send(&self, mut ipv4: Ipv4, tcp: Tcp) {
        use netstack::data_link::Tun;

        // The IP is set in the run.sh script.
        ipv4.src_ip = Ipv4Addr::new([192, 168, 0, 2]);

        let tun = Tun::new(0, EthType::Ip);
        let packet = (tun / ipv4 / tcp).into_boxed_bytes();

        self.0.send(&packet).expect("tun: failed to send packet");
    }
}

pub fn main() -> io::Result<()> {
    let iface = Iface::new("tun0", Mode::Tun)?;
    let device = Arc::new(Tun(iface));

    let mut buf = [0u8; 1504];
    let mut tcp_socket: Option<TcpSocket<Tun>> = None;

    while let Ok(bytes_read) = device.0.recv(&mut buf) {
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
            tcp_socket.recv(tcp, payload);
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

    struct SocketShim(TcpSocket<Tun>);

    impl SocketShim {
        #[inline]
        fn new(socket: TcpSocket<Tun>) -> Self {
            Self(socket)
        }

        fn await_process(&mut self) {
            let mut buf = [0u8; 1504];
            let device = &self.0.device;

            loop {
                if let Ok(bytes_read) = device.0.recv(&mut buf) {
                    let mut packet_parser = PacketParser::new(&buf[..bytes_read]);

                    let tun = packet_parser.next::<data_link::Tun>();

                    if tun.typ != EthType::Ip {
                        continue;
                    }

                    let ipv4 = packet_parser.next::<Ipv4>();

                    if ipv4.protocol != Ipv4Type::Tcp {
                        continue;
                    }

                    let tcp = packet_parser.next::<Tcp>();
                    let options_size = tcp.header_size() as usize - tcp.write_len();
                    let payload = &packet_parser.payload()[options_size..];

                    self.0.recv(tcp, payload);
                    break;
                }
            }
        }
    }

    impl Deref for SocketShim {
        type Target = TcpSocket<Tun>;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl DerefMut for SocketShim {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    fn client_socket(device: Arc<Tun>) -> SocketShim {
        let address = Address::new(4242, 6969, Ipv4Addr::new([192, 168, 0, 2]));
        let socket = TcpSocket::connect(device, address);

        SocketShim::new(socket)
    }

    fn server_socket(device: Arc<Tun>) -> SocketShim {
        let address = Address::new(6969, 4242, Ipv4Addr::new([192, 168, 0, 2]));
        let socket = TcpSocket::new(device, address);

        SocketShim::new(socket)
    }

    macro_rules! run_command {
        ($($t:tt)*) => {{
            use std::process::Command;

            let command = format!($($t)*);
            eprintln!("Running `{command}`");

            let output = Command::new("sh")
                .arg("-c")
                .arg(&command)
                .output()
                .expect("failed to execute process");

            if !output.status.success() {
                panic!("command failed: {}", command);
            }
        }};
    }

    fn tun_device() -> Arc<Tun> {
        let iface = Iface::new("tun1", Mode::Tun).unwrap();
        run_command!("sudo ip addr add 192.168.0.1/24 dev tun1");
        run_command!("sudo ip link set up dev tun1");

        Arc::new(Tun(iface))
    }

    fn socket_pair() -> (SocketShim, SocketShim) {
        let device = tun_device();

        let server = server_socket(device.clone());
        let client = client_socket(device);

        (server, client)
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
}
