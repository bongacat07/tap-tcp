
pub struct ICMP {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub extended_header: u32,
    pub payload: Vec<u8>,
}

pub fn parse_icmp(buf: &[u8]) -> Option<ICMP> {
    if buf.len() < 8 {
        return None;
    }

    Some(ICMP {
        icmp_type: buf[0],
        code: buf[1],
        checksum: u16::from_be_bytes([buf[2], buf[3]]),
        extended_header: u32::from_be_bytes([
            buf[4],
            buf[5],
            buf[6],
            buf[7],
        ]),
        payload: buf[8..].to_vec(),
    })
}
pub fn print_icmp(x: &ICMP) {
    println!("ICMP");
    println!("  Type: {}", x.icmp_type);
    println!("  Code: {}", x.code);
    println!("  Checksum: 0x{:04x}", x.checksum);

    println!(
        "  Identifier: {}",
        (x.extended_header >> 16) as u16
    );

    println!(
        "  Sequence: {}",
        (x.extended_header & 0xffff) as u16
    );

}
