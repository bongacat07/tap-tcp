use tun_tap::Iface;

pub struct ArpPacket {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hardware_size: u8,
    pub protocol_size: u8,
    pub opcode: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}
const MY_MAC: [u8; 6] = [0x06, 0x09, 0x04, 0x02, 0x00, 0x0a];
const MY_IP:  [u8; 4] = [10, 0, 0, 2];


pub fn parse_arp(buf: &[u8]) -> Option<ArpPacket> {
    if buf.len() < 28 {
        return None;
    }
    Some(ArpPacket {
        hardware_type: u16::from_be_bytes([buf[0], buf[1]]),
        protocol_type: u16::from_be_bytes([buf[2], buf[3]]),
        hardware_size: buf[4],
        protocol_size: buf[5],
        opcode:        u16::from_be_bytes([buf[6], buf[7]]),
        sender_mac:    buf[8..14].try_into().unwrap(),
        sender_ip:     buf[14..18].try_into().unwrap(),
        target_mac:    buf[18..24].try_into().unwrap(),
        target_ip:     buf[24..28].try_into().unwrap(),
    })
}

pub fn print_arp(a: &ArpPacket) {
    let op = if a.opcode == 1 { "request" } else { "reply" };
    let src_mac = a.sender_mac.map(|b| format!("{:02x}", b)).join(":");
    let tgt_mac = a.target_mac.map(|b| format!("{:02x}", b)).join(":");
    let src_ip = a.sender_ip;
    let tgt_ip = a.target_ip;

    println!(
        "ARP {} | src {}({}.{}.{}.{}) → tgt {}({}.{}.{}.{})",
        op,
        src_mac, src_ip[0], src_ip[1], src_ip[2], src_ip[3],
        tgt_mac, tgt_ip[0], tgt_ip[1], tgt_ip[2], tgt_ip[3],
    );
}

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
