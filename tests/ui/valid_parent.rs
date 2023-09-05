use netstack::data_link::{Eth, MacAddr};
use netstack::transport::Udp;

fn main() {
    let eth = Eth::new(MacAddr::NULL, MacAddr::NULL, netstack::data_link::Type::Ip);
    let udp = Udp::new(8080, 80);

    let x = eth / udp;
}
