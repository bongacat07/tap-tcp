use tun_tap::{Iface, Mode};
use tap_tcp::eth::ethernet::{EthernetFrame,parse_ethernet_frame,print_ethernet_frame};
use tap_tcp::eth::arp::{parse_arp,ArpPacket,print_arp};

const MY_MAC: [u8; 6] = [0x06, 0x09, 0x04, 0x02, 0x00, 0x0a];
const MY_IP:  [u8; 4] = [10, 0, 0, 2];

pub fn send_arp_reply(iface: &Iface, req: &ArpPacket) {
    let mut buf = Vec::with_capacity(42);

    buf.extend_from_slice(&req.sender_mac);
    buf.extend_from_slice(&MY_MAC);
    buf.extend_from_slice(&0x0806u16.to_be_bytes());
    buf.extend_from_slice(&req.hardware_type.to_be_bytes());
    buf.extend_from_slice(&req.protocol_type.to_be_bytes());
    buf.push(req.hardware_size);
    buf.push(req.protocol_size);
    buf.extend_from_slice(&2u16.to_be_bytes());
    buf.extend_from_slice(&MY_MAC);
    buf.extend_from_slice(&MY_IP);
    buf.extend_from_slice(&req.sender_mac);
    buf.extend_from_slice(&req.sender_ip);
    iface.send(&buf);
}

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
            _ => {

            }
        }

    }
}
