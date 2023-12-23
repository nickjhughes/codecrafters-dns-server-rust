use std::net::UdpSocket;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("received {} bytes from {}", size, source);
                let response = [];
                udp_socket
                    .send_to(&response, source)
                    .expect("failed to send response");
            }
            Err(e) => {
                eprintln!("error receiving data: {}", e);
                break;
            }
        }
    }
}
