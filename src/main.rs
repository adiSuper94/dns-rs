mod message;
mod server;

use message::Message;
use std::net::UdpSocket;

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    let mut server = server::DnsServer::new(parse_cli_args());
    println!("Resolver: {}", server.resolver());
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                match Message::parse(&buf) {
                    Ok((_, m)) => {
                        server.process(m, source, &udp_socket);
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

fn parse_cli_args() -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    let mut opts = getopts::Options::new();
    opts.optopt("r", "resolver", "set persistence directory", "DIR");
    let cli_opts = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!("{}", f.to_string()),
    };
    cli_opts.opt_str("r")
}
