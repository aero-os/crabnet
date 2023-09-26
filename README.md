# `crabnet`
![ci](https://github.com/aero-os/crabnet/actions/workflows/rust.yml/badge.svg)

Rust library for creating and parsing network packets. 

## Features
* Crabnet extensively makes use of the Rust's type system to validate parsing and creation of packets at compile time. 
* The checksum for each layer is automatically computed on packet creation. 
