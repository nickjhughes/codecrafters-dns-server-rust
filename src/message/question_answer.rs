use bytes::BufMut;
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, u8},
    IResult,
};

use super::Message;

const MAX_LABEL_SIZE: usize = 63;

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
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
    Invalid,
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum Class {
    /// IN: The internet.
    Internet = 1,
    /// CS: The CSNET class (Obsolete - used only for examples in some obsolete RFCs).
    CSNet = 2,
    /// CH: The CHAOS class.
    Chaos = 3,
    /// HS: Hesiod [Dyer 87].
    Hesiod = 4,
    Invalid,
}

/// A domain name encoded as a sequence of labels.
#[derive(Debug, Clone)]
pub struct DomainName {
    labels: Vec<Label>,
}

#[derive(Debug, Clone)]
pub enum Label {
    /// A label value as a string.
    Value(String),
    /// A pointer to another label value.
    Pointer(u16),
}

#[derive(Debug)]
pub struct Question {
    /// A domain name.
    pub name: DomainName,
    /// The type of record.
    pub ty: RecordType,
    /// Usually set to 1.
    pub class: Class,
}

#[derive(Debug)]
pub struct ResourceRecord {
    /// The domain name.
    pub name: DomainName,
    /// 1 for an A record, 5 for a CNAME record etc., full list here
    pub ty: RecordType,
    /// Usually set to 1.
    pub class: Class,
    /// TTL: The duration in seconds a record can be cached before requerying.
    pub time_to_live: u32,
    /// RDLENGTH: Length of the data field in bytes.
    pub length: u16,
    /// RDATA: Data specific to the record type.
    pub data: ResourceRecordData,
}

#[derive(Debug)]
pub enum ResourceRecordData {
    /// An IPv4 address.
    IPv4([u8; 4]),
}

impl RecordType {
    fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (rest, byte) = be_u16(input)?;
        let ty = match byte {
            1 => RecordType::Address,
            2 => RecordType::NameServer,
            3 => RecordType::MailDestination,
            4 => RecordType::MailForwarder,
            5 => RecordType::CName,
            6 => RecordType::StartOfAuthority,
            7 => RecordType::Mailbox,
            8 => RecordType::MailGroup,
            9 => RecordType::MailRename,
            10 => RecordType::Null,
            11 => RecordType::WellKnownService,
            12 => RecordType::Pointer,
            13 => RecordType::HostInfo,
            14 => RecordType::MailboxInfo,
            15 => RecordType::MailExchange,
            16 => RecordType::Text,
            _ => RecordType::Invalid,
        };
        Ok((rest, ty))
    }
}

impl Class {
    fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (rest, byte) = be_u16(input)?;
        let class = match byte {
            1 => Class::Internet,
            2 => Class::CSNet,
            3 => Class::Chaos,
            4 => Class::Hesiod,
            _ => Class::Invalid,
        };
        Ok((rest, class))
    }
}

impl DomainName {
    pub fn _new(name: &str) -> anyhow::Result<Self> {
        let mut labels = Vec::new();
        for label in name.split('.') {
            if label.len() > MAX_LABEL_SIZE {
                anyhow::bail!("label cannot be longer than {MAX_LABEL_SIZE} bytes");
            }
            labels.push(Label::Value(label.to_string()));
        }
        Ok(DomainName { labels })
    }

    pub fn length(&self) -> u16 {
        let mut length = 0;
        for label in self.labels.iter() {
            length += match label {
                Label::Value(string) => 1 + string.len() as u16,
                Label::Pointer(_) => 2,
            };
        }
        if matches!(self.labels.last().unwrap(), Label::Value(_)) {
            // Final null byte
            length += 1;
        }
        length
    }

    pub fn get_label(&self, offset: u16) -> anyhow::Result<&str> {
        let mut name_offset = 0;
        for label in self.labels.iter() {
            if offset == name_offset {
                match label {
                    Label::Value(string) => return Ok(string),
                    Label::Pointer(_) => {
                        return Err(anyhow::format_err!("invalid label offset (pointer)"))
                    }
                }
            }
            name_offset += match label {
                Label::Value(string) => 1 + string.len() as u16,
                Label::Pointer(_) => 2,
            };
        }
        Err(anyhow::format_err!(
            "invalid label offset (not start of a label)"
        ))
    }

    pub fn decompress(&self, message: &Message) -> anyhow::Result<Self> {
        let mut labels = Vec::new();
        for label in self.labels.iter() {
            labels.push(match label {
                Label::Value(string) => Label::Value(string.to_owned()),
                Label::Pointer(offset) => Label::Value(message.get_label(*offset)?.to_owned()),
            });
        }
        Ok(DomainName { labels })
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let mut rest = input;
        let mut labels = Vec::new();
        loop {
            let (remainder, label_length) = u8(rest)?;
            rest = remainder;
            if label_length == 0 {
                break;
            } else if (label_length >> 6) == 0x03 {
                // Pointer
                let (remainder, pointer_remainder) = u8(rest)?;
                rest = remainder;
                let pointer = ((label_length & 0x3F) as u16) << 8 | (pointer_remainder as u16);
                labels.push(Label::Pointer(pointer));
                break;
            } else if label_length as usize > MAX_LABEL_SIZE {
                panic!("label cannot be longer than {MAX_LABEL_SIZE} bytes");
            }
            let (remainder, label) = take(label_length)(rest)?;
            rest = remainder;
            labels.push(Label::Value(
                String::from_utf8(label.to_owned()).expect("labels should be valid utf-8"),
            ));
        }
        Ok((rest, DomainName { labels }))
    }

    fn write<B>(&self, buf: &mut B) -> anyhow::Result<()>
    where
        B: BufMut,
    {
        for label in self.labels.iter() {
            match label {
                Label::Value(string) => {
                    if string.len() > MAX_LABEL_SIZE {
                        anyhow::bail!("label cannot be longer than {MAX_LABEL_SIZE} bytes");
                    }
                    buf.put_u8(string.len() as u8);
                    buf.put_slice(string.as_bytes());
                }
                Label::Pointer(_) => todo!(),
            }
        }
        buf.put_u8(0);

        Ok(())
    }
}

impl Question {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (rest, name) = DomainName::parse(input)?;
        let (rest, ty) = RecordType::parse(rest)?;
        let (rest, class) = Class::parse(rest)?;
        Ok((rest, Question { name, ty, class }))
    }

    pub fn length(&self) -> u16 {
        self.name.length() + 4
    }

    pub fn get_label(&self, offset: u16) -> anyhow::Result<&str> {
        if offset >= self.name.length() {
            anyhow::bail!("invalid label offset (in type/class enums)");
        }
        self.name.get_label(offset)
    }

    pub fn write<B>(&self, buf: &mut B) -> anyhow::Result<()>
    where
        B: BufMut,
    {
        self.name.write(buf)?;
        buf.put_u16(self.ty as u16);
        buf.put_u16(self.class as u16);

        Ok(())
    }
}

impl ResourceRecord {
    pub fn new(
        name: DomainName,
        ty: RecordType,
        class: Class,
        time_to_live: u32,
        data: ResourceRecordData,
    ) -> Self {
        ResourceRecord {
            name,
            ty,
            class,
            time_to_live,
            length: data.length(),
            data,
        }
    }

    pub fn parse(_input: &[u8]) -> IResult<&[u8], Self> {
        todo!()
    }

    pub fn write<B>(&self, buf: &mut B) -> anyhow::Result<()>
    where
        B: BufMut,
    {
        self.name.write(buf)?;
        buf.put_u16(self.ty as u16);
        buf.put_u16(self.class as u16);
        buf.put_u32(self.time_to_live);
        self.data.write(buf)?;

        Ok(())
    }
}

impl ResourceRecordData {
    fn length(&self) -> u16 {
        match self {
            ResourceRecordData::IPv4(_) => 4,
        }
    }

    pub fn _parse(_input: &[u8]) -> IResult<&[u8], Self> {
        todo!()
    }

    pub fn write<B>(&self, buf: &mut B) -> anyhow::Result<()>
    where
        B: BufMut,
    {
        buf.put_u16(self.length());
        match self {
            ResourceRecordData::IPv4(ip) => {
                buf.put_slice(ip);
            }
        }
        Ok(())
    }
}
