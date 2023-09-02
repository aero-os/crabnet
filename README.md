## API v1

```rust
let packet = Packet::new(total_size);
let eth = Eth::from_bytes(packet.as_slice_mut());
let ipv4 = Ipv4::from_bytes(eth.payload_mut());

let pseudo_header = PseudoHeader::new(&ipv4);
let udp = Udp::from_pseudo_bytes(pseudo_header, ipv4.payload_mut());

// Flaws:
//     - The checksum is not calculated automatically.
//     - Not enough rusty and like can be improved a lot imo.
```

## API v61
```rust
let udp = Udp::new(0 /* payload_size */); // :: Packet<Udp>
let ipv4 = udp.downgrade(); // :: Packet<Ipv4>
let eth = ipv4.downgrade(); // :: Packet<Eth> 

// Flaws:
//   - upgrade::<Tcp>() can be called on a Packet<Ipv4> which was
//     before a Packet<Udp> (by calling downgrade() on it). This is
//     because PacketHierarchy<T> for Ipv4 is implemented for both UDP 
//     and TCP packets.
//
//   - internally in Udp::new(), Packet::new() is called which allocates the
//     memory for the whole packet. The memory is not in an initialized state.
```

## API v62
```rust
define_stack! { @stack crate::data_link::Eth << crate::network::Ipv4 << crate::transport::Udp; }

let udp = Udp::new(0 /* payload_size */); // :: Packet<stack::Udp>
let ipv4 = udp.downgrade(); // :: Packet<stack::Ipv4>
let eth = ipv4.downgrade(); // :: Packet<stack::Eth>

// Flaws:
//     - Same as in v61, the memory is not initially in an initialized state.
//
// Fixes from v61:
//     - upgrade::<Tcp> cannot be called since it is not part of the stack.
```

## API v69
```rust
let packet: Stacked<Stacked<Ethernet, Ipv4>, Udp> = eth << ip << udp;

// Unresolved issues:
//     - With UDP, to calcualte the checksum, information about the lower layer (Ipv4)
//       is required to make the pseudo header. This is possible with the current API
//       but if another layer is added, the checksum is not recaluclated properly. The
///      same applys for TCP.
```

