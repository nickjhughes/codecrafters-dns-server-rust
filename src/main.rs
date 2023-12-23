use std::net::UdpSocket;

use bytes::BytesMut;
use message::{Header, Message};

mod message;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((_, source)) => {
                let reply_message = Message {
                    header: Header {
                        packet_id: 1234,
                        query_response_indicator: false,
                        op_code: message::OpCode::Query,
                        authoritative_answer: false,
                        truncation: false,
                        recursion_desired: false,
                        recursion_available: false,
                        reserved: 0,
                        response_code: message::ResponseCode::Ok,
                        question_count: 0,
                        answer_record_count: 0,
                        authority_record_count: 0,
                        additional_record_count: 0,
                    },
                };
                let mut response = BytesMut::with_capacity(64);
                reply_message.write(&mut response);
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
