use rand::Rng;
use std::collections::{HashMap, HashSet};
use tap_tcp::checksum::checksum::{checksum, ip_checksum, tcp_checksum};
use tap_tcp::eth::arp::{ArpPacket, parse_arp, print_arp, send_arp_reply};
use tap_tcp::eth::ethernet::{EthernetFrame, parse_ethernet_frame, print_ethernet_frame};
use tap_tcp::icmp::icmp::*;
use tap_tcp::ip::ip::*;
use tap_tcp::tcp::send::*;
use tap_tcp::tcp::tcp::*;
use tap_tcp::udp::quote::get_quote;
use tap_tcp::udp::udp::*;
use tun_tap::{Iface, Mode};
fn main() {
    let iface = Iface::without_packet_info("tap0", Mode::Tap).expect("Failed to create TAP device");

    println!("Listening on tap0");

    let mut buf = vec![0u8; 65535];
    let mut connections: HashMap<ConnectionKey, TCB> = HashMap::new();
    let mut listener: HashSet<u16> = HashSet::new();
    listener.insert(8080);

    loop {
        let n = iface.recv(&mut buf).expect("Failed to recv");
        let packet = &buf[..n];

        let frame = parse_ethernet_frame(&buf);

        match frame.ether_type {
            0x0806 => {
                if let Some(incoming_arp) = parse_arp(&frame.payload) {
                    println!("------------ETHERNET-------------");
                    print_ethernet_frame(&frame);
                    println!("------------ARP-------------");
                    print_arp(&incoming_arp);
                    println!("\n");

                    match incoming_arp.opcode {
                        0x0001 => {
                            println!("ARP Request Recieved");
                            if incoming_arp.target_ip == MY_IP {
                                send_arp_reply(&iface, &incoming_arp);
                                println!("ARP Reply sent");
                            }
                        }

                        0x0002 => {
                            println!("ARP REPLY RECEIVED");
                        }

                        _ => {}
                    }
                }
            }
            0x0800 => {
                if let Some(ipv4) = parse_ipv4(&frame.payload) {
                    match ipv4.header.fields.protocol {
                        1 => {
                            println!("IP Packet recieved");
                            let bytes = serialize_ipv4_header(&ipv4.header);
                            if checksum(&bytes) == 0 {
                                // checksum is valid
                            } else {
                                // checksum is invalid
                            }

                            print_ipv4(&ipv4);
                            if let Some(incoming_icmp) = parse_icmp(&ipv4.payload) {
                                let bytes = serialize_icmp_header(&incoming_icmp.fields);
                                if checksum(&bytes) == 0 {
                                    // checksum is valid
                                } else {
                                    // checksum is invalid
                                }
                                print_icmp(&incoming_icmp);

                                match incoming_icmp.fields.icmp_type {
                                    8 => {
                                        println!("ICMP Echo Request");
                                        send_icmp_echo_reply(&iface, &frame, &ipv4, &incoming_icmp);
                                        println!("ICMP Reply Sent");
                                    }

                                    0 => {
                                        println!("ICMP Echo Reply");
                                    }

                                    _ => {}
                                }
                            }
                        }

                        6 => {
                            println!("TCP Packet recieved");
                            let bytes = serialize_ipv4_header(&ipv4.header);
                            if checksum(&bytes) == 0 {
                                // checksum is valid
                            } else {
                                // checksum is invalid
                                continue;
                            }

                            print_ipv4(&ipv4);
                            if let Some(tcp) = parse_tcp(&ipv4.payload) {
                                print_tcp(&tcp);

                                //Create a connectionKey 4 tuple
                                // The first step is to check whether this connection is being tracked by a TCB or not

                                let key = ConnectionKey {
                                    src_ip: ipv4.header.fields.destination,
                                    src_port: tcp.header.dst_port,
                                    dst_ip: ipv4.header.fields.source,
                                    dst_port: tcp.header.src_port,
                                };

                                if let Some(tcb) = connections.get_mut(&key) {
                                    let flags = tcp.header.flags;
                                    //Regardless of your state, you stop tracking the connection
                                    // when you recieve a RST.
                                    if check_flags(&flags, RST) {
                                        connections.remove(&key);
                                        println!("RST received, connection aborted");
                                        continue;
                                    }
                                    //On identifying that the Key exists
                                    // The state is tracked by the TCB.
                                    // We match based on the current state and handle the packet accordingly.
                                    match tcb.state {
                                        TCPState::SynReceived => {
                                            //The three way handshake =>
                                            // SYN (peer sends this) -> SYN_ACK (local sends this out)-> ACK (peer sends it back)
                                            // Why a 3 way handshake is mentioned in www.ihateabstractions.fun/why-not-a-2-way-handshake
                                            //
                                            // Check if it's an ACK
                                            if check_flags(&flags, ACK) {
                                                //QUITE CRUCIAL:
                                                // Even if it's an ACK, it can be a crated ACK Packet or an ACK not meant for this connection
                                                // Check the recieved ACK'S num with snd_next
                                                //
                                                // Client                         Server
                                                //
                                                //SEQ = x, SYN  -------------------->
                                                //<-------------  SEQ = y, ACK = x+1, SYN
                                                //ACK = y+1  ------------------------->
                                                //

                                                if tcp.header.ack_num == tcb.snd_nxt {
                                                    // Our SYN has been acknowledged.
                                                    // Handshake complete.
                                                    tcb.state = TCPState::Established;
                                                    tcb.snd_una = tcp.header.ack_num;
                                                    println!("Handshake complete");

                                                    //Send RST Because Invalid ACK
                                                } else {
                                                    println!("Invalid ACK");
                                                    send_rst(
                                                        &iface,
                                                        &ipv4.header.fields,
                                                        &tcp.header,
                                                        &frame,
                                                    );
                                                    connections.remove(&key);
                                                    continue;
                                                }

                                                //Send RST because it's not ACK
                                            } else {
                                                send_rst(
                                                    &iface,
                                                    &ipv4.header.fields,
                                                    &tcp.header,
                                                    &frame,
                                                );

                                                //remove Key from TCB
                                                connections.remove(&key);
                                                continue;
                                            }
                                        }
                                        //This is the listener side's implementation. That is: No Initiating the connection.
                                        TCPState::SynSent => {}

                                        TCPState::Established => {
                                            println!("TODO");
                                        }

                                        TCPState::FinWait1 => {
                                            println!("TODO");
                                        }

                                        TCPState::FinWait2 => {
                                            println!("TODO");
                                        }

                                        TCPState::CloseWait => {
                                            println!("TODO");
                                        }

                                        TCPState::Closing => {
                                            println!("TODO");
                                        }

                                        TCPState::LastAck => {
                                            println!("TODO");
                                        }

                                        TCPState::TimeWait => {
                                            println!("TODO");
                                        }

                                        TCPState::Closed => {
                                            println!("TODO");
                                        }
                                    }
                                    //This connection doesn't exist, since the TCB can't identify the 4 tuple
                                } else {
                                    //See if the port number is valid
                                    if !listener.contains(&tcp.header.dst_port) {
                                        send_rst(&iface, &ipv4.header.fields, &tcp.header, &frame);
                                        continue;
                                    }

                                    let flags = tcp.header.flags;
                                    //Check if it's a SYN FLAG
                                    // Meaning, a new connection is to be formed.
                                    // Since it's a SYN, Send a synack
                                    if check_flags(&flags, SYN) && !check_flags(&flags, ACK) {
                                        let iss: u32 = rand::random();
                                        //We insert the approarriate values into the TCB
                                        // Change state to SYN_RECIEVED
                                        connections.insert(
                                            key,
                                            TCB {
                                                state: TCPState::SynReceived,
                                                iss,
                                                snd_una: iss,
                                                snd_nxt: iss.wrapping_add(1),
                                                irs: tcp.header.seq_num,
                                                rcv_nxt: tcp.header.seq_num.wrapping_add(1),
                                            },
                                        );
                                        //Send SYN ACK
                                        send_syn_ack(
                                            &iface,
                                            &ipv4.header.fields,
                                            &tcp.header,
                                            &frame,
                                            iss,
                                        );
                                        println!("SYN received, SYN-ACK sent");
                                        //If it's any other packet, just send RST
                                    } else {
                                        send_rst(&iface, &ipv4.header.fields, &tcp.header, &frame);
                                    }
                                }
                            }
                        }

                        17 => {
                            println!("UDP Packet recieved");
                            let bytes = serialize_ipv4_header(&ipv4.header);
                            if checksum(&bytes) == 0 {
                                // checksum is valid
                            } else {
                                // checksum is invalid
                            }

                            print_ipv4(&ipv4);
                            if let Some(incoming_udp) = parse_udp(&ipv4.payload) {
                                print_udp(&incoming_udp);
                                get_quote(&iface, &incoming_udp, &ipv4, &frame);
                            }
                        }

                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}
