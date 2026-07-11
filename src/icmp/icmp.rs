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
