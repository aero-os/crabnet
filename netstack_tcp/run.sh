#!/bin/sh

EXE=../target/release/netstack_tcp
set -xe

cargo build --release --bin netstack_tcp

# CAP_NET_ADMIN: Allows to perform various network-related operations.
sudo setcap CAP_NET_ADMIN=eip $EXE

RUST_LOG=debug $EXE &
pid=$!
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid

# nc --tcp 192.168.0.2 443
# tshark -i tun0
