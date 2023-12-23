use bytes::BufMut;

#[derive(Debug)]
pub struct Message {
    pub header: Header,
}

#[derive(Debug)]
pub struct Header {
    /// ID: A random ID assigned to query packets. Response packets must reply with the same ID.
    pub packet_id: u16,

    /// QR: 1 for a reply packet, 0 for a question packet.
    pub query_response_indicator: bool,

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
}

impl Message {
    pub fn write<B>(&self, buf: &mut B)
    where
        B: BufMut,
    {
        self.header.write(buf);
    }
}

impl Header {
    pub fn write<B>(&self, buf: &mut B)
    where
        B: BufMut,
    {
        buf.put_u16(self.packet_id);

        let mut byte2 = 0;
        byte2 |= (self.query_response_indicator as u8) << 7;
        byte2 |= (self.op_code as u8) << 3;
        byte2 |= (self.authoritative_answer as u8) << 2;
        byte2 |= (self.truncation as u8) << 1;
        byte2 |= self.recursion_desired as u8;
        buf.put_u8(byte2);

        let mut byte3 = 0;
        byte3 |= (self.recursion_available as u8) << 7;
        byte3 |= (self.reserved as u8) << 4;
        byte3 |= self.response_code as u8;
        buf.put_u8(byte3);

        buf.put_u16(self.question_count);
        buf.put_u16(self.answer_record_count);
        buf.put_u16(self.authority_record_count);
        buf.put_u16(self.additional_record_count);
    }
}
