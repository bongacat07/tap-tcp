use crate::checksum::checksum::*;
use crate::eth::ethernet::*;
use crate::ip::ip::*;

use tun_tap::Iface;

pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub extended_header: u32,
}

pub struct IcmpPacket {
    pub fields: IcmpHeader,
    pub payload: Vec<u8>,
}

pub fn parse_icmp(buf: &[u8]) -> Option<IcmpPacket> {
    if buf.len() < 8 {
        return None;
    }

    Some(IcmpPacket {
        fields: IcmpHeader {
            icmp_type: buf[0],
            code: buf[1],
            checksum: u16::from_be_bytes([buf[2], buf[3]]),
            extended_header: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        },
        payload: buf[8..].to_vec(),
    })
}

pub fn print_icmp(pkt: &IcmpPacket) {
    println!("ICMP");
    println!("  Type: {}", pkt.fields.icmp_type);
    println!("  Code: {}", pkt.fields.code);
    println!("  Checksum: 0x{:04x}", pkt.fields.checksum);

    println!(
        "  Identifier: {}",
        (pkt.fields.extended_header >> 16) as u16
    );

    println!(
        "  Sequence: {}",
        (pkt.fields.extended_header & 0xffff) as u16
    );

    println!("  Payload Length: {}", pkt.payload.len());
}

pub fn serialize_icmp_header(header: &IcmpHeader) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);

    buf.push(header.icmp_type);
    buf.push(header.code);
    buf.extend_from_slice(&header.checksum.to_be_bytes());
    buf.extend_from_slice(&header.extended_header.to_be_bytes());

    buf
}

pub fn send_icmp_echo_reply(
    iface: &Iface,
    eth: &EthernetFrame,
    ipv4: &Ipv4Packet,
    icmp: &IcmpPacket,
) {
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
