pub const MY_IP: [u8; 4] = [10, 0, 0, 2];
#[derive(Clone, Copy)]
pub struct Ipv4HeaderFields {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub source: [u8; 4],
    pub destination: [u8; 4],
}

pub struct Ipv4Header {
    pub fields: Ipv4HeaderFields,
    pub header_checksum: u16,
}
pub struct Ipv4Packet {
    pub header: Ipv4Header,
    pub payload: Vec<u8>,
}

pub fn print_ipv4(h: &Ipv4Packet) {
    println!("\n");
    println!("--- IPv4 Packet ---");
    println!("Version: {}", h.header.fields.version);
    println!("IHL: {}", h.header.fields.ihl);
    println!("Protocol: {}", h.header.fields.protocol);
    println!(
        "Source: {}.{}.{}.{}",
        h.header.fields.source[0],
        h.header.fields.source[1],
        h.header.fields.source[2],
        h.header.fields.source[3]
    );
    println!(
        "Destination: {}.{}.{}.{}",
        h.header.fields.destination[0],
        h.header.fields.destination[1],
        h.header.fields.destination[2],
        h.header.fields.destination[3]
    );
    println!("-------------------");
    println!("\n");
}

pub fn parse_ipv4(buf: &[u8]) -> Option<Ipv4Packet> {
    // Minimum IPv4 header size
    if buf.len() < 20 {
        return None;
    }

    let version = buf[0] >> 4;
    let ihl = buf[0] & 0x0f;

    if version != 4 {
        return None;
    }

    // IHL is in 32-bit words
    if ihl < 5 {
        return None;
    }

    let header_len = (ihl as usize) * 4;

    if buf.len() < header_len {
        return None;
    }

    let total_length = u16::from_be_bytes([buf[2], buf[3]]);

    if total_length < header_len as u16 {
        return None;
    }

    if total_length as usize > buf.len() {
        return None;
    }

    let payload = buf[header_len..total_length as usize].to_vec();

    Some(Ipv4Packet {
        header: Ipv4Header {
            fields: Ipv4HeaderFields {
                version,
                ihl,
                tos: buf[1],
                total_length,

                identification: u16::from_be_bytes([buf[4], buf[5]]),

                flags: buf[6] >> 5,

                fragment_offset: (((buf[6] as u16) & 0x1f) << 8) | buf[7] as u16,

                ttl: buf[8],

                protocol: buf[9],

                source: [buf[12], buf[13], buf[14], buf[15]],

                destination: [buf[16], buf[17], buf[18], buf[19]],
            },

            header_checksum: u16::from_be_bytes([buf[10], buf[11]]),
        },

        payload,
    })
}

pub fn serialize_ipv4_header(header: &Ipv4Header) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20);

    buf.push((header.fields.version << 4) | header.fields.ihl);
    buf.push(header.fields.tos);
    buf.extend_from_slice(&header.fields.total_length.to_be_bytes());
    buf.extend_from_slice(&header.fields.identification.to_be_bytes());
    let flags_fragment = ((header.fields.flags as u16) << 13) | header.fields.fragment_offset;
    buf.extend_from_slice(&flags_fragment.to_be_bytes());
    buf.push(header.fields.ttl);
    buf.push(header.fields.protocol);
    buf.extend_from_slice(&header.header_checksum.to_be_bytes());
    buf.extend_from_slice(&header.fields.source);
    buf.extend_from_slice(&header.fields.destination);
    buf
}
