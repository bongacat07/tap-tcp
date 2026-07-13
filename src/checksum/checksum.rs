use crate::{icmp::icmp::*, ip::ip::*, tcp::tcp::*, udp::udp::*};

pub fn ip_checksum_verifier(header: &Ipv4Header) -> bool {
    let bytes = serialize_ipv4_header(header);
    checksum(&bytes) == 0
}

pub fn icmp_checksum_verifier(header: &IcmpHeader) -> bool {
    let bytes: Vec<u8> = serialize_icmp_header(header);
    checksum(&bytes) == 0
}
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    let mut chunks = data.chunks_exact(2);

    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum += word;
    }

    let rem = chunks.remainder();
    if !rem.is_empty() {
        sum += (rem[0] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

pub fn tcp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], tcp: &TCPPacket) -> u16 {
    let tcp_len = (tcp.header.data_offset as usize * 4 + tcp.payload.len()) as u16;

    let mut buf = Vec::with_capacity(12 + tcp_len as usize);
    buf.extend_from_slice(&src_ip);
    buf.extend_from_slice(&dst_ip);
    buf.push(0);
    buf.push(6);
    buf.extend_from_slice(&tcp_len.to_be_bytes());

    let mut header = tcp.header.clone();
    header.checksum = 0;
    buf.extend_from_slice(&serialize_tcp_header(&header));
    buf.extend_from_slice(&tcp.payload);

    checksum(&buf)
}

pub fn ip_checksum(h: &Ipv4HeaderFields) -> u16 {
    let header = Ipv4Header {
        fields: h.clone(),
        header_checksum: 0,
    };
    checksum(&serialize_ipv4_header(&header))
}
pub fn udp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], udp: &UDPPacket) -> u16 {
    let udp_len = 8 + udp.payload.len() as u16;

    let mut buf = Vec::with_capacity(12 + udp_len as usize);

    buf.extend_from_slice(&src_ip);
    buf.extend_from_slice(&dst_ip);
    buf.push(0);
    buf.push(17);
    buf.extend_from_slice(&udp_len.to_be_bytes());

    buf.extend_from_slice(&udp.header.src_port.to_be_bytes());
    buf.extend_from_slice(&udp.header.dst_port.to_be_bytes());
    buf.extend_from_slice(&udp_len.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());

    buf.extend_from_slice(&udp.payload);

    checksum(&buf)
}
