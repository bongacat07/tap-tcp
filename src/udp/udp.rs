use crate::ip::ip::*;

pub struct UDPHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
}

pub struct UDPPacket {
    pub header: UDPHeader,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

pub fn parse_udp(buf: &[u8]) -> Option<UDPPacket> {
    if buf.len() < 8 {
        return None;
    }

    Some(UDPPacket {
        header: UDPHeader {
            src_port: u16::from_be_bytes([buf[0], buf[1]]),
            dst_port: u16::from_be_bytes([buf[2], buf[3]]),
            length: u16::from_be_bytes([buf[4], buf[5]]),
        },
        checksum: u16::from_be_bytes([buf[6], buf[7]]),
        payload: buf[8..].to_vec(),
    })
}
pub fn serialize_udp_header(packet: &UDPHeader) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);

    buf.extend_from_slice(&packet.src_port.to_be_bytes());
    buf.extend_from_slice(&packet.dst_port.to_be_bytes());
    buf.extend_from_slice(&packet.length.to_be_bytes());

    buf
}

pub fn print_udp(u: &UDPPacket) {
    println!(
        "UDP | {} → {} | len {} | checksum 0x{:04x} | payload {} bytes",
        u.header.src_port,
        u.header.dst_port,
        u.header.length,
        u.checksum,
        u.payload.len(),
    );
}

pub fn create_udp_packet(udp: &UDPPacket, ip: &Ipv4Header) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ip.fields.total_length as usize);

    buf.extend_from_slice(&serialize_ipv4_header(ip));

    buf.extend_from_slice(&udp.header.src_port.to_be_bytes());
    buf.extend_from_slice(&udp.header.dst_port.to_be_bytes());
    buf.extend_from_slice(&udp.header.length.to_be_bytes());
    buf.extend_from_slice(&udp.checksum.to_be_bytes());

    buf.extend_from_slice(&udp.payload);

    buf
}
