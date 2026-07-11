use tap_tcp::checksum::checksum::checksum;
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
                            if let Some(incoming_tcp) = parse_tcp(&ipv4.payload) {
                                print_tcp(&incoming_tcp);
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
