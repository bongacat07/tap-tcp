use crate::checksum::checksum::*;
use crate::eth::ethernet::*;
use crate::ip::ip::*;
use crate::tcp::tcp::*;
use tun_tap::Iface;
pub fn send_rst(
    iface: &Iface,
    recv_ip: &Ipv4HeaderFields,
    recv_tcp: &TCPHeader,
    eth: &EthernetFrame,
) {
    let mut tcp_packet = TCPPacket {
        header: TCPHeader {
            src_port: recv_tcp.dst_port,
            dst_port: recv_tcp.src_port,
            seq_num: recv_tcp.ack_num,
            ack_num: recv_tcp.seq_num.wrapping_add(1),
            data_offset: 5,
            flags: 0x04,
            window: 0,
            checksum: 0,
            urgent_ptr: 0,
        },
        payload: vec![],
    };

    let ip_fields = Ipv4HeaderFields {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: 40,
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        ttl: 64,
        protocol: 6,
        source: recv_ip.destination,
        destination: recv_ip.source,
    };

    tcp_packet.header.checksum = tcp_checksum(ip_fields.source, ip_fields.destination, &tcp_packet);

    let ip_header = Ipv4Header {
        fields: ip_fields,
        header_checksum: ip_checksum(&ip_fields),
    };

    let ip_tcp_buf = create_packet(&tcp_packet, &ip_header);

    let mut frame = Vec::new();
    frame.extend_from_slice(&eth.src_mac);
    frame.extend_from_slice(&MY_MAC);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ip_tcp_buf);

    iface.send(&frame).expect("failed to send RST");
    println!("RST sent");
}

pub fn send_ack(
    iface: &Iface,
    recv_ip: &Ipv4HeaderFields,
    recv_tcp: &TCPHeader,
    eth: &EthernetFrame,
    seq: u32,
    ack: u32,
) {
    let mut tcp_packet = TCPPacket {
        header: TCPHeader {
            src_port: recv_tcp.dst_port,
            dst_port: recv_tcp.src_port,
            seq_num: seq,
            ack_num: ack,
            data_offset: 5,
            flags: 0x10,
            window: 64240,
            checksum: 0,
            urgent_ptr: 0,
        },
        payload: vec![],
    };

    let ip_fields = Ipv4HeaderFields {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: 40,
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        ttl: 64,
        protocol: 6,
        source: recv_ip.destination,
        destination: recv_ip.source,
    };

    tcp_packet.header.checksum = tcp_checksum(ip_fields.source, ip_fields.destination, &tcp_packet);

    let ip_header = Ipv4Header {
        fields: ip_fields,
        header_checksum: ip_checksum(&ip_fields),
    };

    let ip_tcp_buf = create_packet(&tcp_packet, &ip_header);

    let mut frame = Vec::new();
    frame.extend_from_slice(&eth.src_mac);
    frame.extend_from_slice(&MY_MAC);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ip_tcp_buf);

    iface.send(&frame).expect("failed to send ACK");
    println!("ACK sent");
}

pub fn send_syn_ack(
    iface: &Iface,
    recv_ip: &Ipv4HeaderFields,
    recv_tcp: &TCPHeader,
    eth: &EthernetFrame,
    seq: u32,
) {
    let mut tcp_packet = TCPPacket {
        header: TCPHeader {
            src_port: recv_tcp.dst_port,
            dst_port: recv_tcp.src_port,
            seq_num: seq,
            ack_num: recv_tcp.seq_num.wrapping_add(1),
            data_offset: 5,
            flags: 0x12,
            window: 64240,
            checksum: 0,
            urgent_ptr: 0,
        },
        payload: vec![],
    };

    let ip_fields = Ipv4HeaderFields {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: 40,
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        ttl: 64,
        protocol: 6,
        source: recv_ip.destination,
        destination: recv_ip.source,
    };

    tcp_packet.header.checksum = tcp_checksum(ip_fields.source, ip_fields.destination, &tcp_packet);

    let ip_header = Ipv4Header {
        fields: ip_fields,
        header_checksum: ip_checksum(&ip_fields),
    };

    let ip_tcp_buf = create_packet(&tcp_packet, &ip_header);

    let mut frame = Vec::new();
    frame.extend_from_slice(&eth.src_mac);
    frame.extend_from_slice(&MY_MAC);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ip_tcp_buf);
    iface.send(&frame).expect("failed to send SYN-ACK");
    println!("SYN-ACK sent");
}

pub fn create_packet(x: &TCPPacket, y: &Ipv4Header) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();

    buf.push((y.fields.version << 4) | y.fields.ihl);
    buf.push(y.fields.tos);
    buf.extend_from_slice(&y.fields.total_length.to_be_bytes());
    buf.extend_from_slice(&y.fields.identification.to_be_bytes());
    let flags_frag = ((y.fields.flags as u16) << 13) | y.fields.fragment_offset;
    buf.extend_from_slice(&flags_frag.to_be_bytes());
    buf.push(y.fields.ttl);
    buf.push(y.fields.protocol);
    buf.extend_from_slice(&y.header_checksum.to_be_bytes());
    buf.extend_from_slice(&y.fields.source);
    buf.extend_from_slice(&y.fields.destination);

    buf.extend_from_slice(&x.header.src_port.to_be_bytes());
    buf.extend_from_slice(&x.header.dst_port.to_be_bytes());
    buf.extend_from_slice(&x.header.seq_num.to_be_bytes());
    buf.extend_from_slice(&x.header.ack_num.to_be_bytes());
    let data_offset_and_flags: u16 =
        ((x.header.data_offset as u16) << 12) | (x.header.flags & 0x1FF);
    buf.extend_from_slice(&data_offset_and_flags.to_be_bytes());
    buf.extend_from_slice(&x.header.window.to_be_bytes());
    buf.extend_from_slice(&x.header.checksum.to_be_bytes());
    buf.extend_from_slice(&x.header.urgent_ptr.to_be_bytes());
    buf.extend_from_slice(&x.payload);

    buf
}

/// Sends a FIN+ACK for the given connection.
///
/// `dst_mac` is the Ethernet address the frame should be sent to. This is
/// explicit rather than hardcoded because the two callers know it
/// differently:
///   - The active opener (e.g. `minc`) already knows its peer's MAC as a
///     fixed constant, since it initiated the connection to a known address.
///   - The passive listener (e.g. `tap_tcp`) only knows the peer's MAC from
///     whatever frame it last received (`eth.src_mac`), since it could be
///     talking to any host that connects to it.
/// Hardcoding a single constant here would silently break the listener case.
pub fn send_fin_ack(key: &ConnectionKey, tcb: &mut TCB, iface: &Iface, dst_mac: [u8; 6]) {
    let seq = tcb.snd_nxt;
    let ack = tcb.rcv_nxt;

    let mut tcp_packet = TCPPacket {
        header: TCPHeader {
            src_port: key.src_port,
            dst_port: key.dst_port,
            seq_num: seq,
            ack_num: ack,
            data_offset: 5,
            flags: FIN_ACK,
            window: 64240,
            checksum: 0,
            urgent_ptr: 0,
        },
        payload: vec![],
    };
    let ip_fields = Ipv4HeaderFields {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: 40, // 20 (IP) + 20 (TCP, no payload)
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        ttl: 64,
        protocol: 6,
        source: key.src_ip,
        destination: key.dst_ip,
    };

    tcp_packet.header.checksum = tcp_checksum(ip_fields.source, ip_fields.destination, &tcp_packet);

    let ip_header = Ipv4Header {
        fields: ip_fields,
        header_checksum: ip_checksum(&ip_fields),
    };

    let ip_tcp_buf = create_packet(&tcp_packet, &ip_header);

    let mut frame = Vec::new();
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&MY_MAC);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ip_tcp_buf);

    iface.send(&frame).expect("failed to send FIN_ACK");
    println!("FIN_ACK sent");
}
