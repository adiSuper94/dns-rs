mod message;

use message::Message;
use std::net::UdpSocket;

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                match Message::deserialize(buf) {
                    Ok(mut m) => {
                        m.header.qr = true;
                        m.header.qdcount = m.questions.len() as u16;
                        m.header.id = 1234;
                        let response = m.serialize();
                        udp_socket
                            .send_to(&response, source)
                            .expect("Failed to send response");
                    }
                    Err(e) => {
                        eprintln!("Failed to parse message: {}", e);
                        continue;
                    }
                };
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
