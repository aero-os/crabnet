use netstack::data_link::{Eth, EthType, MacAddr};
use netstack::transport::Udp;

fn main() {
    let eth = Eth::new(MacAddr::NULL, MacAddr::NULL, EthType::Ip);
    let udp = Udp::new(8080, 80);

    let x = eth / udp;
}
