use bytes::BufMut;

#[derive(Debug)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    // pub answers: Vec<ResourceRecord>,
    // pub authorities: Vec<ResourceRecord>,
    // pub additionals: Vec<ResourceRecord>,
}

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

#[derive(Debug)]
pub struct Question {
    /// A domain name.
    pub name: String,
    /// The type of record.
    pub ty: RecordType,
    /// Usually set to 1.
    pub class: Class,
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
#[allow(dead_code)]
pub enum RecordType {
    /// A: A host address.
    Address = 1,
    /// NS: An authoritative name server.
    NameServer = 2,
    /// MD: A mail destination (Obsolete - use MX).
    MailDestination = 3,
    /// MF: A mail forwarder (Obsolete - use MX).
    MailForwarder = 4,
    /// CNAME: The canonical name for an alias.
    CName = 5,
    /// SOA: Marks the start of a zone of authority.
    StartOfAuthority = 6,
    /// MB: A mailbox domain name (EXPERIMENTAL).
    Mailbox = 7,
    /// MG: A mail group member (EXPERIMENTAL).
    MailGroup = 8,
    /// MR: A mail rename domain name (EXPERIMENTAL).
    MailRename = 9,
    /// NULL: A null RR (EXPERIMENTAL).
    Null = 10,
    /// WKS: A well known service description.
    WellKnownService = 11,
    /// PTR: A domain name pointer.
    Pointer = 12,
    /// HINFO: Host information.
    HostInfo = 13,
    /// MINFO: Mailbox or mail list information.
    MailboxInfo = 14,
    /// MX: Mail exchange.
    MailExchange = 15,
    /// TXT: Text strings.
    Text = 16,
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
#[allow(dead_code)]
pub enum Class {
    /// IN: The internet.
    Internet = 1,
    /// CS: The CSNET class (Obsolete - used only for examples in some obsolete RFCs).
    CSNet = 2,
    /// CH: The CHAOS class.
    Chaos = 3,
    /// HS: Hesiod [Dyer 87].
    Hesiod = 4,
}

impl Message {
    pub fn parse(buf: &[u8]) -> anyhow::Result<Self> {
        let header = Header::parse(buf)?;
        Ok(Message {
            header,
            questions: Vec::new(),
        })
    }

    pub fn new_reply(query_message: &Message, questions: Vec<Question>) -> Self {
        Message {
            header: Header {
                packet_id: query_message.header.packet_id,
                is_response: true,
                op_code: OpCode::Query,
                authoritative_answer: false,
                truncation: false,
                recursion_desired: false,
                recursion_available: false,
                reserved: 0,
                response_code: ResponseCode::Ok,
                question_count: questions.len() as u16,
                answer_record_count: 0,
                authority_record_count: 0,
                additional_record_count: 0,
            },
            questions,
        }
    }

    pub fn write<B>(&self, buf: &mut B) -> anyhow::Result<()>
    where
        B: BufMut,
    {
        self.header.write(buf);
        for question in self.questions.iter() {
            question.write(buf)?;
        }
        Ok(())
    }
}

impl Header {
    pub fn parse(buf: &[u8]) -> anyhow::Result<Self> {
        let packet_id = u16::from_be_bytes([buf[0], buf[1]]);

        let is_response = (buf[2] >> 7) & 0x01 != 0;
        let op_code = OpCode::parse((buf[2] >> 3) & 0x0F)?;
        let authoritative_answer = (buf[2] >> 2) & 0x01 != 0;
        let truncation = (buf[2] >> 1) & 0x01 != 0;
        let recursion_desired = buf[2] & 0x01 != 0;

        let recursion_available = (buf[3] >> 7) & 0x01 != 0;
        let reserved = (buf[3] >> 4) & 0x07;
        let response_code = ResponseCode::parse(buf[3] & 0x0F)?;

        let question_count = u16::from_be_bytes([buf[4], buf[5]]);
        let answer_record_count = u16::from_be_bytes([buf[6], buf[7]]);
        let authority_record_count = u16::from_be_bytes([buf[8], buf[9]]);
        let additional_record_count = u16::from_be_bytes([buf[10], buf[11]]);

        Ok(Header {
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
        })
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
    fn parse(input: u8) -> anyhow::Result<Self> {
        match input {
            0 => Ok(OpCode::Query),
            1 => Ok(OpCode::IQuery),
            2 => Ok(OpCode::Status),
            _ => Err(anyhow::format_err!("invalid OPCODE {input}")),
        }
    }
}

impl ResponseCode {
    fn parse(input: u8) -> anyhow::Result<Self> {
        match input {
            0 => Ok(ResponseCode::Ok),
            1 => Ok(ResponseCode::FormatError),
            2 => Ok(ResponseCode::ServerFailure),
            3 => Ok(ResponseCode::NameError),
            4 => Ok(ResponseCode::NotImplemented),
            5 => Ok(ResponseCode::Refused),
            _ => Err(anyhow::format_err!("invalid RCODE {input}")),
        }
    }
}

impl Question {
    pub fn write<B>(&self, buf: &mut B) -> anyhow::Result<()>
    where
        B: BufMut,
    {
        for label in self.name.split('.') {
            if label.len() > u8::MAX as usize {
                anyhow::bail!("label cannot be longer than {} bytes", u8::MAX);
            }
            buf.put_u8(label.len() as u8);
            buf.put_slice(label.as_bytes());
        }
        buf.put_u8(0);

        buf.put_u16(self.ty as u16);
        buf.put_u16(self.class as u16);

        Ok(())
    }
}
