use bytes::BytesMut;
use std::net::UdpSocket;

use message::{Message, Question};

mod message;

fn main() -> anyhow::Result<()> {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((_, source)) => {
                let query_message = Message::parse(&buf)?;
                let mut reply_message = Message::new_reply(
                    &query_message,
                    vec![Question {
                        name: "codecrafters.io".into(),
                        ty: message::RecordType::Address,
                        class: message::Class::Internet,
                    }],
                );
                reply_message.header.packet_id = 1234;
                let mut response = BytesMut::with_capacity(64);
                reply_message.write(&mut response)?;
                udp_socket
                    .send_to(&response, source)
                    .expect("failed to send response");
            }
            Err(e) => {
                anyhow::bail!("error receiving data: {}", e);
            }
        }
    }
}
