use bytes::BufMut;
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, u8},
    IResult,
};

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
    Invalid,
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
    Invalid,
}

/// A domain name encoded as a sequence of labels.
#[derive(Debug, Clone)]
pub struct DomainName {
    labels: Vec<String>,
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
    #[allow(dead_code)]
    pub fn new(name: &str) -> anyhow::Result<Self> {
        let mut labels = Vec::new();
        for label in name.split('.') {
            if label.len() > u8::MAX as usize {
                anyhow::bail!("label cannot be longer than {} bytes", u8::MAX);
            }
            labels.push(label.to_string());
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
            }
            let (remainder, label) = take(label_length)(rest)?;
            rest = remainder;
            labels.push(String::from_utf8(label.to_owned()).expect("labels should be valid utf-8"));
        }
        Ok((rest, DomainName { labels }))
    }

    fn write<B>(&self, buf: &mut B) -> anyhow::Result<()>
    where
        B: BufMut,
    {
        for label in self.labels.iter() {
            if label.len() > u8::MAX as usize {
                anyhow::bail!("label cannot be longer than {} bytes", u8::MAX);
            }
            buf.put_u8(label.len() as u8);
            buf.put_slice(label.as_bytes());
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
