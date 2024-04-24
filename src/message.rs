use anyhow::{bail, Result};
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32, be_u8},
    IResult,
};

pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Answer>,
}

impl Message {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bites = self.header.to_bytes();
        bites.extend(self.questions.iter().flat_map(|q| q.to_bytes()));
        bites.extend(self.answers.iter().flat_map(|a| a.to_bytes()));
        return bites;
    }

    pub fn parse(bites: &[u8]) -> IResult<&[u8], Message> {
        let (mut bites, header) = Header::parse(bites)?;
        let mut questions = vec![];
        let mut question: Question;
        for _ in 0..header.qdcount {
            (bites, question) = Question::parse(bites)?;
            questions.push(question);
        }
        let mut answers = vec![];
        let mut answer: Answer;
        for _ in 0..header.ancount {
            (bites, answer) = Answer::parse(bites)?;
            answers.push(answer);
        }
        return Ok((bites, Message { header, questions, answers }));
    }

    fn parse_label_seq(bites: &[u8]) -> IResult<&[u8], Vec<String>> {
        let mut name = vec![];
        let (mut bites, mut lable_len) = be_u8(bites)?;
        let mut label_bites: &[u8];
        loop {
            (bites, label_bites) = take(lable_len)(bites)?;
            let label = String::from_utf8_lossy(label_bites).to_string();
            name.push(label);
            (bites, lable_len) = be_u8(bites)?;
            if lable_len == 0 {
                break;
            }
        }
        return Ok((bites, name));
    }

}

pub struct Header {
    pub id: u16,
    /// query or response: 0 for question, 1 for reply
    pub qr: bool,
    /// specifies the type of query in a message
    opcode: u8,
    /// authoritative answer: 1 if the responding server is authoritative for/ owns the domain name in question
    pub aa: bool,
    /// truncation: 1 is message was larger than 512 bytes, and was truncated
    pub tc: bool,
    /// recursion desired: 1 if the client wants the server to recursively resolve the query
    rd: bool,
    /// recursion available: server sets this to 1 if it supports recursion
    pub ra: bool,
    /// Reserved: Used by DNSSEC queries.
    pub z: u8,
    /// response code: indicates the status of the response. 0 if no error
    pub rcode: u8,
    /// number of questions in the question section
    pub qdcount: u16,
    /// number of records in answer section
    pub ancount: u16,
    /// number of records in authority section
    nscount: u16,
    /// number of records in additional section
    arcount: u16,
}

impl Header {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bites = vec![];
        bites.push((self.id >> 8) as u8);
        bites.push(self.id as u8);
        bites.push(
            (if self.qr { 1 << 7 } else { 0 })
                | ((self.opcode << 3) & 0b01111000)
                | (if self.aa { 1 << 2 } else { 0 })
                | (if self.tc { 1 << 1 } else { 0 })
                | (if self.rd { 1 } else { 0 }),
        );
        bites.push(
            (if self.ra { 1 << 7 } else { 0 })
                | ((self.z << 4) & 0b01110000)
                | (self.rcode & 0b00001111),
        );
        bites.push((self.qdcount >> 8) as u8);
        bites.push(self.qdcount as u8);
        bites.push((self.ancount >> 8) as u8);
        bites.push(self.ancount as u8);
        bites.push((self.nscount >> 8) as u8);
        bites.push(self.nscount as u8);
        bites.push((self.arcount >> 8) as u8);

        bites.push(self.arcount as u8);
        return bites;
    }

    fn parse(bites: &[u8]) -> IResult<&[u8], Header> {
        let (bites, id) = be_u16(bites)?;
        let (bites, sec_bite) = be_u8(bites)?;
        let qr = sec_bite & 0b10000000 == 128;
        let opcode = (sec_bite & 0b01111000) >> 3;
        let aa = sec_bite & 0b00000100 == 4;
        let tc = sec_bite & 0b00000010 == 2;
        let rd = sec_bite & 0b00000001 == 1;
        let (bites, third_bite) = be_u8(bites)?;
        let ra = third_bite & 0b10000000 == 128;
        let z = (third_bite & 0b01110000) >> 4;
        let rcode = third_bite & 0b00001111;
        let (bites, qdcount) = be_u16(bites)?;
        let (bites, ancount) = be_u16(bites)?;
        let (bites, nscount) = be_u16(bites)?;
        let (bites, arcount) = be_u16(bites)?;
        return Ok((
            bites,
            Header {
                id,
                qr,
                opcode,
                aa,
                tc,
                rd,
                ra,
                z,
                rcode,
                qdcount,
                ancount,
                nscount,
                arcount,
            },
        ));
    }
}

pub enum QType {
    /// A host address
    A,
    /// An authoritative name server
    NS,
    /// A mail destination
    MD,
    /// A mail forwarder
    MF,
    /// The canonical name for an alias
    CNAME,
    /// Marks the start of a zone of authority
    SOA,
    /// A mailbox domain name
    MB,
    /// A mail group member
    MG,
    /// A mail rename domain name
    MR,
    /// A null resource record
    NULL,
    /// A well known service description
    WKS,
    /// A domain name pointer
    PTR,
    /// Host information
    HINFO,
    /// Mailbox or mail list information
    MINFO,
    /// Mail exchange
    MX,
    /// Text strings
    TXT,
}

impl QType {
    fn value(&self) -> u16 {
        match self {
            QType::A => 1,
            QType::NS => 2,
            QType::MD => 3,
            QType::MF => 4,
            QType::CNAME => 5,
            QType::SOA => 6,
            QType::MB => 7,
            QType::MG => 8,
            QType::MR => 9,
            QType::NULL => 10,
            QType::WKS => 11,
            QType::PTR => 12,
            QType::HINFO => 13,
            QType::MINFO => 14,
            QType::MX => 15,
            QType::TXT => 16,
        }
    }

    fn from_value(value: u16) -> Result<QType> {
        match value {
            1 => Ok(QType::A),
            2 => Ok(QType::NS),
            3 => Ok(QType::MD),
            4 => Ok(QType::MF),
            5 => Ok(QType::CNAME),
            6 => Ok(QType::SOA),
            7 => Ok(QType::MB),
            8 => Ok(QType::MG),
            9 => Ok(QType::MR),
            10 => Ok(QType::NULL),
            11 => Ok(QType::WKS),
            12 => Ok(QType::PTR),
            13 => Ok(QType::HINFO),
            14 => Ok(QType::MINFO),
            15 => Ok(QType::MX),
            16 => Ok(QType::TXT),
            _ => bail!("Unknown QType value: {}", value),
        }
    }
}

pub enum ResourceClass {
    /// the Internet
    IN,
    /// the CSNET class
    CS,
    /// the CHAOS class
    CH,
    /// Hesiod [Dyer 87]
    HS,
}

impl ResourceClass {
    fn from_value(value: u16) -> Result<ResourceClass> {
        match value {
            1 => Ok(ResourceClass::IN),
            2 => Ok(ResourceClass::CS),
            3 => Ok(ResourceClass::CH),
            4 => Ok(ResourceClass::HS),
            _ => bail!("Unknown ResourseClass value: {}", value),
        }
    }
    fn value(&self) -> u16 {
        match self {
            ResourceClass::IN => 1,
            ResourceClass::CS => 2,
            ResourceClass::CH => 3,
            ResourceClass::HS => 4,
        }
    }
}

pub struct Question {
    pub tipe: QType,
    pub class: ResourceClass,
    pub name: Vec<String>,
}

impl Question {

    fn parse(bites: &[u8]) -> IResult<&[u8], Question> {
        let (bites, name) = Message::parse_label_seq(bites)?;
        let (bites, tipe) = be_u16(bites)?;
        let tipe = match QType::from_value(tipe) {
            Ok(t) => t,
            Err(_e) => {
                return Err(nom::Err::Failure(nom::error::Error::new(
                    bites,
                    nom::error::ErrorKind::Tag,
                )))
            }
        };
        let (bites, class) = be_u16(bites)?;
        let class = match ResourceClass::from_value(class) {
            Ok(c) => c,
            Err(_e) => {
                return Err(nom::Err::Failure(nom::error::Error::new(
                    bites,
                    nom::error::ErrorKind::Tag,
                )))
            }
        };
        return Ok((bites, Question { tipe, class, name }));
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bites = vec![];
        for label in &self.name {
            bites.push(label.len() as u8);
            bites.extend(label.as_bytes());
        }
        bites.push(0);
        let tipe_val = self.tipe.value();
        bites.push((tipe_val >> 8) as u8);
        bites.push(tipe_val as u8);
        let class_val = self.class.value();
        bites.push((class_val >> 8) as u8);
        bites.push(class_val as u8);
        return bites;
    }
}

pub struct Answer {
    pub name: Vec<String>,
    pub tipe: QType,
    pub class: ResourceClass,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: Vec<u8>,
}

impl Answer{
    fn parse(bites: &[u8]) -> IResult<&[u8], Answer> {
        let (bites, name) = Message::parse_label_seq(bites)?;
        let (bites, tipe) = be_u16(bites)?;
        let tipe = match QType::from_value(tipe) {
            Ok(t) => t,
            Err(_e) => {
                return Err(nom::Err::Failure(nom::error::Error::new(
                    bites,
                    nom::error::ErrorKind::Tag,
                )))
            }
        };
        let (bites, class) = be_u16(bites)?;
        let class = match ResourceClass::from_value(class) {
            Ok(c) => c,
            Err(_e) => {
                return Err(nom::Err::Failure(nom::error::Error::new(
                    bites,
                    nom::error::ErrorKind::Tag,
                )))
            }
        };
        let (bites, ttl) = be_u32(bites)?;
        let (bites, rdlength) = be_u16(bites)?;
        let (bites, rdata) = take(rdlength)(bites)?;
        return Ok((bites, Answer { name, tipe, class, ttl, rdlength, rdata: rdata.to_vec()}));
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bites = vec![];
        for label in &self.name {
            bites.push(label.len() as u8);
            bites.extend(label.as_bytes());
        }
        bites.push(0);
        let tipe_val = self.tipe.value();
        bites.push((tipe_val >> 8) as u8);
        bites.push(tipe_val as u8);
        let class_val = self.class.value();
        bites.push((class_val >> 8) as u8);
        bites.push(class_val as u8);
        bites.push((self.ttl >> 24) as u8);
        bites.push((self.ttl >> 16) as u8);
        bites.push((self.ttl >> 8) as u8);
        bites.push(self.ttl as u8);
        bites.push((self.rdlength >> 8) as u8);
        bites.push(self.rdlength as u8);
        bites.extend(&self.rdata);
        return bites;
    }
}
