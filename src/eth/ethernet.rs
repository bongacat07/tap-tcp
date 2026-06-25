pub struct EthernetFrame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
    pub payload: Vec<u8>,
}

pub fn parse_ethernet_frame(buf: &[u8]) -> EthernetFrame {
    EthernetFrame {
        dst_mac:    buf[0..6].try_into().unwrap(),
        src_mac:    buf[6..12].try_into().unwrap(),
        ether_type: u16::from_be_bytes([buf[12], buf[13]]),
        payload:    buf[14..].to_vec(),
    }
}

pub fn print_ethernet_frame(x: &EthernetFrame) {
    let dst = x.dst_mac.map(|b| format!("{:02x}", b)).join(":");
    let src = x.src_mac.map(|b| format!("{:02x}", b)).join(":");


    println!("dst {:>17}  src {:>17}  type 0x{:04x}", dst, src, x.ether_type);
}
