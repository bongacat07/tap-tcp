use crate::{icmp::icmp::*, ip::ip::*};

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
