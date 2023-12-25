use bytes::BufMut;
use nom::{
    number::complete::{be_u16, u8},
    IResult,
};
use rand::Rng;

#[derive(Debug)]
pub struct Header {
    /// ID: A random ID assigned to query packets. Response packets must reply with the same ID.
    pub packet_id: u16,
    /// QR: 1 for a reply packet, 0 for a question packet.
    pub is_response: bool,
    /// OPCODE: Specifies the kind of query in a message. 4 bytes.
    pub op_code: OpCode,
    /// AA: 1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    pub authoritative_answer: bool,
    /// TC: 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    pub truncation: bool,
    /// RD: Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    pub recursion_desired: bool,
    /// RA: Server sets this to 1 to indicate that recursion is available.
    pub recursion_available: bool,
    /// Z: Used by DNSSEC queries. At inception, it was reserved for future use. 3 bits.
    pub reserved: u8,
    /// RCODE: Response code indicating the status of the response. 4 bits.
    pub response_code: ResponseCode,
    /// QDCOUNT: Number of questions in the Question section.
    pub question_count: u16,
    /// ANCOUNT: Number of records in the Answer section.
    pub answer_record_count: u16,
    /// NSCOUNT: Number of records in the Authority section.
    pub authority_record_count: u16,
    /// ARCOUNT: Number of records in the Additional section.
    pub additional_record_count: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum OpCode {
    /// QUERY: A standard query.
    Query = 0,
    /// IQUERY: An inverse query.
    IQuery = 1,
    /// STATUS: A server status request.
    Status = 2,
    Invalid,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum ResponseCode {
    /// No error condition.
    Ok = 0,
    /// Format error - The name server was unable to interpret the query.
    FormatError = 1,
    /// Server failure - The name server was unable to process this query due to a
    ///                  problem with the name server.
    ServerFailure = 2,
    /// Name Error - Meaningful only for responses from an authoritative name server,
    /// this code signifies that the domain name referenced in the query does not exist.
    NameError = 3,
    /// Not Implemented - The name server does not support the requested kind of query.
    NotImplemented = 4,
    /// Refused - The name server refuses to perform the specified operation for policy
    ///           reasons. For example, a name server may not wish to provide the
    ///           information to the particular requester, or a name server may not wish
    ///           to perform a particular operation (e.g., zone transfer) for particular data.
    Refused = 5,
    Invalid,
}

impl Header {
    pub fn new_query(question_count: u16) -> Self {
        let mut rng = rand::thread_rng();
        Header {
            packet_id: rng.gen::<u16>(),
            is_response: false,
            op_code: OpCode::Query,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: false,
            recursion_available: false,
            reserved: 0,
            response_code: ResponseCode::Ok,
            question_count,
            answer_record_count: 0,
            authority_record_count: 0,
            additional_record_count: 0,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (rest, packet_id) = be_u16(input)?;

        let (rest, byte2) = u8(rest)?;
        let is_response = (byte2 >> 7) & 0x01 != 0;
        let op_code = OpCode::parse((byte2 >> 3) & 0x0F);
        let authoritative_answer = (byte2 >> 2) & 0x01 != 0;
        let truncation = (byte2 >> 1) & 0x01 != 0;
        let recursion_desired = byte2 & 0x01 != 0;

        let (rest, byte3) = u8(rest)?;
        let recursion_available = (byte3 >> 7) & 0x01 != 0;
        let reserved = (byte3 >> 4) & 0x07;
        let response_code = ResponseCode::parse(byte3 & 0x0F);

        let (rest, question_count) = be_u16(rest)?;
        let (rest, answer_record_count) = be_u16(rest)?;
        let (rest, authority_record_count) = be_u16(rest)?;
        let (rest, additional_record_count) = be_u16(rest)?;

        Ok((
            rest,
            Header {
                packet_id,
                is_response,
                op_code,
                authoritative_answer,
                truncation,
                recursion_desired,
                recursion_available,
                reserved,
                response_code,
                question_count,
                answer_record_count,
                authority_record_count,
                additional_record_count,
            },
        ))
    }

    pub fn write<B>(&self, buf: &mut B)
    where
        B: BufMut,
    {
        buf.put_u16(self.packet_id);

        let mut byte2 = 0;
        byte2 |= (self.is_response as u8) << 7;
        byte2 |= (self.op_code as u8) << 3;
        byte2 |= (self.authoritative_answer as u8) << 2;
        byte2 |= (self.truncation as u8) << 1;
        byte2 |= self.recursion_desired as u8;
        buf.put_u8(byte2);

        let mut byte3 = 0;
        byte3 |= (self.recursion_available as u8) << 7;
        byte3 |= self.reserved << 4;
        byte3 |= self.response_code as u8;
        buf.put_u8(byte3);

        buf.put_u16(self.question_count);
        buf.put_u16(self.answer_record_count);
        buf.put_u16(self.authority_record_count);
        buf.put_u16(self.additional_record_count);
    }
}

impl OpCode {
    fn parse(input: u8) -> Self {
        match input {
            0 => OpCode::Query,
            1 => OpCode::IQuery,
            2 => OpCode::Status,
            _ => OpCode::Invalid,
        }
    }
}

impl ResponseCode {
    fn parse(input: u8) -> Self {
        match input {
            0 => ResponseCode::Ok,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            _ => ResponseCode::Invalid,
        }
    }
}
