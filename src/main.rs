use tun_tap::{Iface, Mode};
use tap_tcp::eth::ethernet::{EthernetFrame,parse_ethernet_frame,print_ethernet_frame};
use tap_tcp::eth::arp::{parse_arp,ArpPacket,print_arp,send_arp_reply};
use tap_tcp::ip::ip::{parse_ipv4,print_ipv4, Ipv4Packet};
use tap_tcp::icmp::icmp::{parse_icmp,print_icmp,ICMP};
use tap_tcp::checksum::checksum::checksum;

 fn send_icmp_echo_reply( iface: &Iface,eth: &EthernetFrame,ipv4: &Ipv4Packet,icmp: &ICMP,) {
    let mut icmp_buf = Vec::new();

        icmp_buf.push(0);
        icmp_buf.push(0);
        icmp_buf.extend_from_slice(&[0, 0]); // checksum placeholder
        icmp_buf.extend_from_slice(&icmp.extended_header.to_be_bytes());
        icmp_buf.extend_from_slice(&icmp.payload);
        let icmp_checksum = checksum(&icmp_buf);
        icmp_buf[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());


        let total_length = (20 + icmp_buf.len()) as u16;
        let mut ip_buf = Vec::new();
        ip_buf.push((4 << 4) | 5);
        ip_buf.push(0);
        ip_buf.extend_from_slice(&total_length.to_be_bytes());
        ip_buf.extend_from_slice(&0u16.to_be_bytes());
        ip_buf.extend_from_slice(&0u16.to_be_bytes());
        ip_buf.push(64);
        ip_buf.push(1);
        ip_buf.extend_from_slice(&[0, 0]);
        ip_buf.extend_from_slice(&MY_IP);
        ip_buf.extend_from_slice(&ipv4.header.fields.source);
        let ip_checksum = checksum(&ip_buf[..20]);
        ip_buf[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        ip_buf.extend_from_slice(&icmp_buf);

        let mut frame = Vec::new();
        frame.extend_from_slice(&eth.src_mac);
        frame.extend_from_slice(&MY_MAC);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&ip_buf);
        iface.send(&frame).expect("failed to send");
    }


const MY_MAC: [u8; 6] = [0x06, 0x09, 0x04, 0x02, 0x00, 0x0a];
const MY_IP:  [u8; 4] = [10, 0, 0, 2];



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
                            println!("ICMP Packet recieved");
                            print_ipv4(&ipv4);
                            if let Some(incoming_icmp) = parse_icmp(&ipv4.payload) {
                                print_icmp(&incoming_icmp);

                                match incoming_icmp.icmp_type {
                                    8 => {
                                        println!("ICMP Echo Request");
                                        send_icmp_echo_reply(&iface,&frame,&ipv4,&incoming_icmp);
                                        println!("ICMP Reply Sent");
                                    }

                                    0 => {
                                        println!("ICMP Echo Reply");
                                    }

                                    _ => {}
                                }
                            }


                        }
                        _ => {}
                    }
                }

            }
            _ => {

            }
        }

    }
}
