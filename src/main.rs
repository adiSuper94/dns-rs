mod message;

use message::{Answer, Message, QType, ResourceClass};
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
                match Message::parse(&buf) {
                    Ok((_, mut m)) => {
                        m = update_message(m);
                        let response = m.to_bytes();
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

fn update_message(mut m: Message) -> Message {
    m.header.qr = true;
    m.header.aa = false;
    m.header.tc = false;
    m.header.ra = false;
    m.header.z = 0;
    m.header.rcode = 4;
    m.header.qdcount = m.questions.len() as u16;
    m.header.ancount = 1;
    m.answers =vec![];
    let ans = Answer{
        name:vec!["codecrafters".to_string(), "io".to_string()],
        tipe: QType::A,
        class: ResourceClass::IN,
        ttl: 60,
        rdlength: 4,
        rdata: vec![127, 0, 0, 1],
    };
    m.answers.push(ans);
    m
}
