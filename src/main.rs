use bytes::BytesMut;
use std::net::UdpSocket;

mod message;

fn main() -> anyhow::Result<()> {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((_, source)) => {
                let query_message = message::Message::parse(&buf)?;

                let reply_message = message::Message::new_reply(
                    &query_message,
                    vec![message::Question {
                        name: message::DomainName::new("codecrafters.io")?,
                        ty: message::RecordType::Address,
                        class: message::Class::Internet,
                    }],
                    vec![message::ResourceRecord::new(
                        message::DomainName::new("codecrafters.io")?,
                        message::RecordType::Address,
                        message::Class::Internet,
                        60,
                        message::ResourceRecordData::IPv4([8, 8, 8, 8]),
                    )],
                );

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
