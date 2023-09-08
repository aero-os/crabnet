use netstack::data_link::{Eth, MacAddr};
use netstack::network::{Ipv4, Ipv4Addr, Ipv4Type};
use netstack::transport::Udp;
use netstack::IntoBoxedBytes;

pub fn main() {
    let eth = Eth::new(MacAddr::NULL, MacAddr::NULL, netstack::data_link::Type::Ip);
    let ip = Ipv4::new(Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST, Ipv4Type::Udp);
    let udp = Udp::new(8080, 80);

    let packet = eth / ip / udp / [69u8; 4];
    println!("{:?}", packet.into_boxed_bytes());
}
