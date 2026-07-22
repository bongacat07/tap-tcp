# TAP-Stack

A simple userspace networking stack built on top of a Linux **TAP** interface. The project is an experimental implementation of networking protocols that allows packets to be received and transmitted directly from userspace without relying on the kernel's TCP/IP stack.

> **Status:** Work in progress. This project is intended for learning and experimentation.

---
## Why am I crazy enough to build a userspace netwokring stack?

Is this the most optimised code? No, not at all. Production grade? Nope. No chance. But did it demistify every layer of networking? Yes. That was the goal.
I am genuinely just writing it on my own, testing it with nc and tcpdump and other tools along each step to see if it holds. No tutorials, so all choices, either smart or dumb was made by me. 

Another goal with this project was to make sure anyone who reads it, sort of understands the lifecycle of a packet. Not the journey of it through the kernel, (That's a whole different beast) but in the sense, how the headers are parsed, how the checksums are computed and how the TCP state transitions happen. So I made an attempt to make the code as readable and simple as possible.

---
## Features

* Userspace packet processing
* Linux TAP interface integration
* Foundation for implementing Ethernet, IPv4, ARP, ICMP, TCP, and other protocols
* Written in Rust

---

## Prerequisites

Before running the project, ensure you have:

* Linux (TAP devices are Linux-specific)
* Rust and Cargo installed
* Root privileges (required to create and configure TAP interfaces)

---

## Building

Compile the project in release mode:

```bash
cargo build --release
```

---

## Running

Creating and configuring a TAP interface requires root privileges.

Start the application:

```bash
sudo ./target/release/tap-tcp
```

---

## Configuring the TAP Interface

Bring the interface up:

```bash
sudo ip link set tap0 up
```

Assign it an IP address:

```bash
sudo ip addr add 10.0.0.1/24 dev tap0
```

Verify the configuration:

```bash
ip addr show tap0
```

Expected output:

```text
tap0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 10.0.0.1/24 scope global tap0
```

---

## Testing Connectivity

You can verify that the interface has been created successfully:

```bash
ip link show tap0
```

Display the assigned IP address:

```bash
ip addr show tap0
```

Capture packets exchanged through the TAP interface:

```bash
sudo tcpdump -i tap0
```

---

## Cleanup

Remove the assigned IP address:

```bash
sudo ip addr flush dev tap0
```

Bring the interface down:

```bash
sudo ip link set tap0 down
```

If the interface was created manually:

```bash
sudo ip tuntap del dev tap0 mode tap
```

---

## Roadmap

* [X] Ethernet frame parsing
* [X] ARP implementation
* [X] IPv4 packet parsing
* [X] ICMP (Ping)
* [X] UDP support
* [ ] TCP implementation
* [ ] Routing
* [ ] Packet checksum validation
* [ ] Logging and debugging utilities

---


Anyone can use it, I don't really care. But feel free to reach out, if for some reason you decide to use it and found this useful and get me a scoop of Ice Cream.
