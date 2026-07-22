use crate::{checksum::checksum::*, eth::ethernet::*, ip::ip::*, udp::udp::*};
use tun_tap::Iface;

const QUOTES: [&str; 10] = [
    "Computer science is no more about computers than astronomy is about telescopes. — Edsger W. Dijkstra",
    "Programs must be written for people to read, and only incidentally for machines to execute. — Harold Abelson & Gerald Jay Sussman",
    "The question of whether a computer can think is no more interesting than the question of whether a submarine can swim. — Edsger W. Dijkstra",
    "Measuring programming progress by lines of code is like measuring aircraft building progress by weight. — Bill Gates",
    "Controlling complexity is the essence of computer programming. — Brian Kernighan",
    "Talk is cheap. Show me the code. — Linus Torvalds",
    "The function of good software is to make the complex appear to be simple. — Grady Booch",
    "The best way to predict the future is to invent it. — Alan Kay",
    "Any fool can write code that a computer can understand. Good programmers write code that humans can understand. — Martin Fowler",
    "Premature optimization is the root of all evil. — Donald Knuth",
];

pub fn get_quote(iface: &Iface, recv_udp: &UDPPacket, recv_ip: &Ipv4Packet, eth: &EthernetFrame) {
    let Some(&opcode) = recv_udp.payload.first() else {
        return;
    };
    if opcode != 1 {
        return;
    }

    use rand::prelude::IndexedRandom;

    let mut rng = rand::rng();
    let payload = QUOTES.choose(&mut rng).unwrap().as_bytes().to_vec();

    let mut udp_packet = UDPPacket {
        header: UDPHeader {
            src_port: recv_udp.header.dst_port,
            dst_port: recv_udp.header.src_port,
            length: (8 + payload.len()) as u16,
        },
        checksum: 0,
        payload,
    };

    udp_packet.checksum = udp_checksum(
        recv_ip.header.fields.destination,
        recv_ip.header.fields.source,
        &udp_packet,
    );

    let ip_fields = Ipv4HeaderFields {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: (20 + udp_packet.header.length) as u16,
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        ttl: 64,
        protocol: 17,
        source: recv_ip.header.fields.destination,
        destination: recv_ip.header.fields.source,
    };

    let ip_header = Ipv4Header {
        fields: ip_fields,
        header_checksum: ip_checksum(&ip_fields),
    };

    let ip_udp_buf = create_udp_packet(&udp_packet, &ip_header);

    let mut frame = Vec::new();
    frame.extend_from_slice(&eth.src_mac);
    frame.extend_from_slice(&MY_MAC);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ip_udp_buf);

    iface.send(&frame).expect("failed to send UDP response");
    println!("UDP quote sent");
}
