use tun_tap::{Iface, Mode};

fn main() {
    let iface = Iface::new("tap0", Mode::Tap).expect("Failed to create TAP device");


    println!("Listening on tap0... (bring it up with: sudo ip link set tap0 up)");

    let mut buf = vec![0u8; 1504];

    loop {
        let n = iface.recv(&mut buf).expect("Failed to recv");
        let packet = &buf[..n];

        println!("--- Got {} bytes ---", n);


        for (i, chunk) in packet.chunks(16).enumerate() {
            print!("{:04x}  ", i * 16);
            for byte in chunk {
                print!("{:02x} ", byte);
            }
            println!();
        }

    }
}
