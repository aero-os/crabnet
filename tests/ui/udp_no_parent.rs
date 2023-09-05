use netstack::transport::Udp;
use netstack::Packet;

fn main() {
    let x = Udp::new(8080, 80) / [69u8; 4];
    let p = Packet::new(x);

    let x = Udp::new(8080, 80);
    let p = Packet::new(x);
}
