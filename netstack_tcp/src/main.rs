use netstack::data_link::EthType;
use netstack::network::{Ipv4, Ipv4Type};
use netstack::transport::Tcp;
use netstack::{IntoBoxedBytes, PacketParser, Protocol};
use netstack_tcp::{NetworkDevice, Socket as TcpSocket};
use std::io;
use std::sync::Arc;
use tun_tap::{Iface, Mode};

/// <https://www.kernel.org/doc/Documentation/networking/tuntap.txt>
struct Tun(Iface);

impl NetworkDevice for Tun {
    fn send(&self, ipv4: Ipv4, tcp: Tcp) {
        use netstack::data_link::Tun;

        let tun = Tun::new(0, EthType::Ip);
        let packet = (tun / ipv4 / tcp).into_boxed_bytes();

        self.0.send(&packet).expect("tun: failed to send packet");
    }
}

pub fn main() -> io::Result<()> {
    env_logger::init();

    let iface = Iface::new("tun0", Mode::Tun)?;
    let device = Arc::new(Tun(iface));

    let mut buf = [0u8; 1504];
    let mut tcp_socket = TcpSocket::new(device.clone());

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

        tcp_socket.recv(ipv4, tcp, payload);
    }

    Ok(())
}
