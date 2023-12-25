use bytes::BytesMut;
use std::{
    env,
    net::{SocketAddrV4, UdpSocket},
};

mod message;

fn forward(
    query_message: message::Message,
    resolver_addr: SocketAddrV4,
    udp_socket: &UdpSocket,
) -> anyhow::Result<message::Message> {
    let mut answers = Vec::new();
    for question in query_message.questions.iter() {
        let questions = vec![message::Question {
            name: question.name.decompress(&query_message)?,
            ty: question.ty,
            class: question.class,
        }];
        let query_message = message::Message::new_query(questions);

        let mut msg = BytesMut::with_capacity(64);
        query_message.write(&mut msg)?;
        udp_socket
            .send_to(&msg, resolver_addr)
            .expect("failed to forward question");
        let mut buf = [0; 512];
        match udp_socket.recv_from(&mut buf) {
            Ok(_) => {
                let response_message = message::Message::parse(&buf)?;
                for answer in response_message.answers.iter() {
                    answers.push(answer.decompressed_clone(&response_message)?);
                }
            }
            Err(e) => {
                anyhow::bail!("error receiving data: {}", e);
            }
        }
    }
    Ok(message::Message::new_reply(
        &query_message,
        query_message
            .questions
            .iter()
            .map(|q| q.decompressed_clone(&query_message).unwrap())
            .collect(),
        answers,
    ))
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let resolver_addr = if args.len() == 3 && args[1] == "--resolver" {
        args[2].parse::<SocketAddrV4>()?
    } else {
        anyhow::bail!("error: no resolver address given")
    };

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("failed to bind to address");
    let mut buf = [0; 512];
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((_, source)) => {
                let query_message = message::Message::parse(&buf)?;
                let response_message = forward(query_message, resolver_addr, &udp_socket)?;
                let mut response = BytesMut::with_capacity(64);
                response_message.write(&mut response)?;
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
