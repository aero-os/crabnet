use crabnet::data_link::{Eth, EthType, MacAddr};
use crabnet::transport::Udp;

fn main() {
    let eth = Eth::new(MacAddr::NULL, MacAddr::NULL, EthType::Ip);
    let udp = Udp::new(8080, 80);

    let x = eth / udp;
}
