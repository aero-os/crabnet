use netstack::transport::Udp;
use netstack::IntoBoxedBytes;

fn main() {
    let x = Udp::new(8080, 80) / [69u8; 4];
    let p = x.into_boxed_bytes();

    let x = Udp::new(8080, 80);
    let p = x.into_boxed_bytes();
}
