use rand::Rng;
use std::collections::{HashMap, HashSet};
use tap_tcp::checksum::checksum::{checksum, ip_checksum, tcp_checksum};
use tap_tcp::eth::arp::{ArpPacket, parse_arp, print_arp, send_arp_reply};
use tap_tcp::eth::ethernet::{EthernetFrame, parse_ethernet_frame, print_ethernet_frame};
use tap_tcp::icmp::icmp::*;
use tap_tcp::ip::ip::*;
use tap_tcp::tcp::tcp::*;
use tap_tcp::udp::udp::*;
use tun_tap::{Iface, Mode};

fn send_icmp_echo_reply(iface: &Iface, eth: &EthernetFrame, ipv4: &Ipv4Packet, icmp: &IcmpPacket) {
    let mut icmp_header = IcmpHeader {
        icmp_type: 0,
        code: 0,
        checksum: 0,
        extended_header: icmp.fields.extended_header,
    };

    let mut icmp_buf = serialize_icmp_header(&icmp_header);
    icmp_buf.extend_from_slice(&icmp.payload);

    let icmp_checksum = checksum(&icmp_buf);
    icmp_header.checksum = icmp_checksum;
    let mut icmp_buf = serialize_icmp_header(&icmp_header);
    icmp_buf.extend_from_slice(&icmp.payload);

    let total_length = (20 + icmp_buf.len()) as u16;
    let mut ip_header = Ipv4Header {
        fields: Ipv4HeaderFields {
            version: 4,
            ihl: 5,
            tos: 0,
            total_length,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol: 1,
            source: MY_IP,
            destination: ipv4.header.fields.source,
        },
        header_checksum: 0,
    };

    let ip_buf_for_checksum = serialize_ipv4_header(&ip_header);
    let ip_checksum = checksum(&ip_buf_for_checksum[..20]);
    ip_header.header_checksum = ip_checksum;

    let mut ip_buf = serialize_ipv4_header(&ip_header);
    ip_buf.extend_from_slice(&icmp_buf);

    let mut frame = Vec::new();
    frame.extend_from_slice(&eth.src_mac);
    frame.extend_from_slice(&MY_MAC);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ip_buf);

    iface.send(&frame).expect("failed to send");
}
const MY_MAC: [u8; 6] = [0x06, 0x09, 0x04, 0x02, 0x00, 0x0a];
const MY_IP: [u8; 4] = [10, 0, 0, 2];

fn main() {
    let iface = Iface::without_packet_info("tap0", Mode::Tap).expect("Failed to create TAP device");

    println!("Listening on tap0");

    let mut buf = vec![0u8; 1504];
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
                            }

                            print_ipv4(&ipv4);
                            if let Some(tcp) = parse_tcp(&ipv4.payload) {
                                print_tcp(&tcp);

                                let key = ConnectionKey {
                                    src_ip: ipv4.header.fields.source,
                                    src_port: tcp.header.src_port,
                                    dst_ip: ipv4.header.fields.destination,
                                    dst_port: tcp.header.dst_port,
                                };

                                if let Some(tcb) = connections.get_mut(&key) {
                                    let flags = tcp.header.flags;

                                    if check_flags(&flags, RST) {
                                        connections.remove(&key);
                                        println!("RST received, connection aborted");
                                        continue;
                                    }
                                    match tcb.state {
                                        TCPState::SynReceived => {
                                            if check_flags(&flags, ACK) {
                                                if tcp.header.ack_num == tcb.snd_nxt {
                                                    tcb.state = TCPState::Established;
                                                    tcb.snd_una = tcp.header.ack_num;

                                                    println!("Handshake complete");
                                                } else {
                                                    println!("Invalid ACK");
                                                    //send rst
                                                    continue;
                                                }
                                            } else {
                                                //send rst
                                                connections.remove(&key);
                                                continue;
                                            }
                                        }
                                        TCPState::SynSent => {
                                            println!("SynSent: TODO");
                                            continue;
                                        }
                                        TCPState::Established => {
                                            if flags & 0x02 != 0 {
                                                println!("Duplicate SYN in Established");
                                                //send rst
                                                connections.remove(&key);
                                                continue;
                                            }

                                            if flags & 0x18 == 0x18 {}
                                            if flags & 0x01 != 0 {
                                                if tcp.header.seq_num == tcb.rcv_nxt {
                                                    println!("Fin Recieved");
                                                    tcb.rcv_nxt += 1;
                                                    //send ack
                                                    tcb.state = TCPState::CloseWait;
                                                }
                                            }
                                        }
                                        TCPState::FinWait1 => {
                                            println!("FinWait1: TODO");
                                            continue;
                                        }
                                        TCPState::FinWait2 => {
                                            println!("FinWait2: TODO");
                                            continue;
                                        }
                                        TCPState::CloseWait => {
                                            //send fin
                                            tcb.snd_nxt += 1;
                                            tcb.state = TCPState::LastAck;
                                        }
                                        TCPState::Closing => {
                                            println!("Closing: TODO");
                                            continue;
                                        }
                                        TCPState::LastAck => {
                                            if (flags & 0x10) != 0 && (flags & 0x02) == 0 {
                                                if tcp.header.ack_num == tcb.snd_nxt {
                                                    println!(
                                                        "Last ACK received, connection closed"
                                                    );
                                                    connections.remove(&key);
                                                } else {
                                                    println!("Invalid ACK");
                                                    //send rst
                                                }
                                            }
                                        }
                                        TCPState::TimeWait => {
                                            println!("TimeWait: TODO");
                                            continue;
                                        }
                                        TCPState::Closed => {
                                            connections.remove(&key);
                                            continue;
                                        }
                                    }
                                } else {
                                    if !listener.contains(&tcp.header.dst_port) {
                                        let recv_ip = &ipv4.header.fields;
                                        let recv_tcp = &tcp.header;
                                        // send_rst(&dev, &h.header.fields, &tcp.header);
                                        continue;
                                    }
                                    let flags = tcp.header.flags;
                                    if (flags & 0x02) != 0 && (flags & 0x10) == 0 {
                                        let recv_ip = &ipv4.header.fields;
                                        let recv_tcp = &tcp.header;
                                        let iss: u32 = rand::random();
                                        let mut tcp_packet = TCPPacket {
                                            header: TCPHeader {
                                                src_port: recv_tcp.dst_port,
                                                dst_port: recv_tcp.src_port,
                                                seq_num: iss,
                                                ack_num: recv_tcp.seq_num + 1,
                                                data_offset: 5,
                                                flags: 0x12,
                                                window: 64240,
                                                checksum: 0,
                                                urgent_ptr: 0,
                                            },
                                            payload: vec![],
                                        };

                                        let ip_fields = Ipv4HeaderFields {
                                            version: 4,
                                            ihl: 5,
                                            tos: 0,
                                            total_length: 40,
                                            identification: 0,
                                            flags: 0,
                                            fragment_offset: 0,
                                            ttl: 64,
                                            protocol: 6,
                                            source: recv_ip.destination,
                                            destination: recv_ip.source,
                                        };

                                        let ip_chk = ip_checksum(&ip_fields);
                                        let tcp_chk = tcp_checksum(
                                            recv_ip.destination,
                                            recv_ip.source,
                                            &tcp_packet,
                                        );
                                        tcp_packet.header.checksum = tcp_chk;

                                        let ip_header = Ipv4Header {
                                            fields: ip_fields,
                                            header_checksum: ip_chk,
                                        };
                                        connections.insert(
                                            key,
                                            TCB {
                                                state: TCPState::SynReceived,

                                                iss,
                                                snd_una: iss,
                                                snd_nxt: iss + 1,

                                                irs: tcp.header.seq_num,
                                                rcv_nxt: tcp.header.seq_num + 1,
                                            },
                                        );
                                        //let packet = create_packet(&tcp_packet, &ip_header);
                                        //dev.send(&packet);

                                        println!("SYN received, SYN-ACK sent");
                                    } else {
                                        //send_rst(&dev, &h.header.fields, &tcp.header);
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
