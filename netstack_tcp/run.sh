#!/bin/sh

istest=false

while getopts "t" flag; do
    case $flag in
        t)
            istest=true
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            ;;
    esac
done

EXE=../target/release/netstack_tcp
set -xe

if [ "$istest" = true ]; then
    EXE=$(cargo test --message-format=json --no-run | \
        jq -r 'select(.reason == "compiler-artifact") | select(.target.kind.[0] == "bin") | .executable')
fi

cargo build --release --bin netstack_tcp

# CAP_NET_ADMIN: Allows to perform various network-related operations.
sudo setcap CAP_NET_ADMIN=eip $EXE
$EXE --nocapture

# RUST_LOG=debug $EXE --nocapture &
# pid=$!
# sudo ip addr add 192.168.0.1/24 dev tun0
# sudo ip link set up dev tun0
# trap "kill $pid" INT TERM
# wait $pid

# # nc --tcp 192.168.0.2 443
# # tshark -i tun0
