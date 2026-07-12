pub const SYN: u16 = 0b0000_0000_0000_0010;
pub const ACK: u16 = 0b0000_0000_0001_0000;
pub const FIN: u16 = 0b0000_0000_0000_0001;
pub const RST: u16 = 0b0000_0000_0000_0100;
pub const PSH: u16 = 0b0000_0000_0000_1000;
pub const URG: u16 = 0b0000_0000_0010_0000;

pub struct TCPHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

pub enum TCPState {
    Closed,
    SynSent,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    SynReceived,
    Established,
}
pub struct TCB {
    pub state: TCPState,
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub rcv_nxt: u32,
    pub irs: u32,
    pub iss: u32,
}
#[derive(Hash, Eq, PartialEq)]
pub struct ConnectionKey {
    pub src_ip: [u8; 4],
    pub src_port: u16,
    pub dst_ip: [u8; 4],
    pub dst_port: u16,
}

pub struct TCPPacket {
    pub header: TCPHeader,
    pub payload: Vec<u8>,
}

pub fn parse_tcp(buf: &[u8]) -> Option<TCPPacket> {
    if buf.len() < 20 {
        return None;
    }

    let data_offset = (buf[12] >> 4) * 4;

    if buf.len() < data_offset as usize {
        return None;
    }

    let header = TCPHeader {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
        seq_num: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        ack_num: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        data_offset,
        flags: ((buf[12] as u16 & 0x01) << 8) | buf[13] as u16,
        window: u16::from_be_bytes([buf[14], buf[15]]),
        checksum: u16::from_be_bytes([buf[16], buf[17]]),
        urgent_ptr: u16::from_be_bytes([buf[18], buf[19]]),
    };

    let payload = buf[data_offset as usize..].to_vec();

    Some(TCPPacket { header, payload })
}

pub fn print_tcp(tcp: &TCPPacket) {
    let h = &tcp.header;
    let f = h.flags & 0b00111111;

    let flag_str = match f {
        0b000010 => "SYN".to_string(),
        0b010010 => "SYN-ACK".to_string(),
        0b010000 => "ACK".to_string(),
        0b000001 => "FIN".to_string(),
        0b010001 => "FIN-ACK".to_string(),
        0b000100 => "RST".to_string(),
        0b011000 => "PSH-ACK".to_string(),
        _ => {
            let mut s = Vec::new();
            if f & 0b100000 != 0 {
                s.push("URG")
            }
            if f & 0b010000 != 0 {
                s.push("ACK")
            }
            if f & 0b001000 != 0 {
                s.push("PSH")
            }
            if f & 0b000100 != 0 {
                s.push("RST")
            }
            if f & 0b000010 != 0 {
                s.push("SYN")
            }
            if f & 0b000001 != 0 {
                s.push("FIN")
            }
            s.join("-")
        }
    };

    println!("--- TCP ---");
    println!("Src Port: {}", h.src_port);
    println!("Dst Port: {}", h.dst_port);
    println!("Seq:      {}", h.seq_num);
    println!("Ack:      {}", h.ack_num);
    println!("Flags:    {}", flag_str);
    println!("-----------");
}

pub fn check_flags(incoming_flags: &u16, tcp_flags: u16) -> bool {
    return (incoming_flags & tcp_flags != 0);
}
