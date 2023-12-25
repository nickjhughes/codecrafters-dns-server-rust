use bytes::BufMut;
use nom::multi::count;

pub use header::Header;
pub use question_answer::{
    Class, DomainName, Question, RecordType, ResourceRecord, ResourceRecordData,
};

mod header;
mod question_answer;

#[derive(Debug)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

impl Message {
    pub fn new_query(questions: Vec<Question>) -> Self {
        Message {
            header: Header::new_query(questions.len() as u16),
            questions,
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    pub fn new_reply(
        query_message: &Message,
        questions: Vec<Question>,
        answers: Vec<ResourceRecord>,
    ) -> Self {
        Message {
            header: Header {
                packet_id: query_message.header.packet_id,
                is_response: true,
                op_code: query_message.header.op_code,
                authoritative_answer: false,
                truncation: false,
                recursion_desired: query_message.header.recursion_desired,
                recursion_available: false,
                reserved: 0,
                response_code: match query_message.header.op_code {
                    header::OpCode::Query => header::ResponseCode::Ok,
                    _ => header::ResponseCode::NotImplemented,
                },
                question_count: questions.len() as u16,
                answer_record_count: answers.len() as u16,
                authority_record_count: 0,
                additional_record_count: 0,
            },
            questions,
            answers,
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    pub fn parse(input: &[u8]) -> anyhow::Result<Self> {
        let (rest, header) = Header::parse(input).map_err(|e| e.map_input(|s| s.to_owned()))?;
        let (rest, questions) = count(Question::parse, header.question_count as usize)(rest)
            .map_err(|e| e.map_input(|s| s.to_owned()))?;
        let (rest, answers) =
            count(ResourceRecord::parse, header.answer_record_count as usize)(rest)
                .map_err(|e| e.map_input(|s| s.to_owned()))?;
        let (rest, authorities) = count(
            ResourceRecord::parse,
            header.authority_record_count as usize,
        )(rest)
        .map_err(|e| e.map_input(|s| s.to_owned()))?;
        let (_rest, additionals) = count(
            ResourceRecord::parse,
            header.additional_record_count as usize,
        )(rest)
        .map_err(|e| e.map_input(|s| s.to_owned()))?;
        Ok(Message {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    pub fn write<B>(&self, buf: &mut B) -> anyhow::Result<()>
    where
        B: BufMut,
    {
        self.header.write(buf);
        for question in self.questions.iter() {
            question.write(buf)?;
        }
        for answer in self.answers.iter() {
            answer.write(buf)?;
        }
        for authority in self.authorities.iter() {
            authority.write(buf)?;
        }
        for additional in self.additionals.iter() {
            additional.write(buf)?;
        }
        Ok(())
    }

    pub fn get_labels(&self, offset: u16) -> anyhow::Result<Vec<String>> {
        if offset < 12 {
            anyhow::bail!("invalid label offset (in header)");
        }
        let mut msg_offset = 12;
        for question in self.questions.iter() {
            if offset < msg_offset + question.length() {
                return question.get_labels(offset - msg_offset);
            }
            msg_offset += question.length();
        }
        Err(anyhow::format_err!(
            "invalid label offset (after questions)"
        ))
    }
}
