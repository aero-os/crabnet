use crabnet::data_link::{Eth, EthType, MacAddr};
use crabnet::network::{Ipv4, Ipv4Addr, Ipv4Type};
use crabnet::transport::Udp;
use crabnet::IntoBoxedBytes;

pub fn main() {
    let eth = Eth::new(MacAddr::NULL, MacAddr::NULL, EthType::Ip);
    let ip = Ipv4::new(Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST, Ipv4Type::Udp);
    let udp = Udp::new(8080, 80);

    let packet = eth / ip / udp / [69u8; 4];
    println!("{:?}", packet.into_boxed_bytes());
}
