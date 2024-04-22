use anyhow::{bail, Context, Result};

pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
}

impl Message {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bites = self.header.serialize();
        bites.extend(self.questions.iter().flat_map(|q| q.serialize()));
        return bites;
    }

    pub fn deserialize(bites: [u8; 512]) -> Result<Message> {
        let header_bites = bites[0..12].to_vec();
        let header = Header::derserialize(header_bites)?;
        let mut bite_iter = bites[12..].iter().peekable();
        let mut questions = vec![];
        for _ in 0..header.qdcount {
            let mut question_bites = vec![];
            loop {
                if let Some(bite) = bite_iter.next() {
                    if *bite == 0 {
                        question_bites.push(*bite);
                        break;
                    } else {
                        question_bites.push(*bite);
                    }
                } else {
                    bail!("Invalid input, couldn't read label length");
                }
            }
            question_bites.extend(bite_iter.by_ref().take(4));
            let question = Question::deserialize(question_bites)?;
            questions.push(question);
        }
        return Ok(Message { header, questions });
    }
}

pub struct Header {
    pub id: u16,
    /// query or response: 0 for question, 1 for reply
    pub qr: bool,
    /// specifies the type of query in a message
    opcode: u8,
    /// authoritative answer: 1 if the responding server is authoritative for/ owns the domain name in question
    aa: bool,
    /// truncation: 1 is message was larger than 512 bytes, and was truncated
    tc: bool,
    /// recursion desired: 1 if the client wants the server to recursively resolve the query
    rd: bool,
    /// recursion available: server sets this to 1 if it supports recursion
    ra: bool,
    /// Reserved: Used by DNSSEC queries.
    z: u8,
    /// response code: indicates the status of the response. 0 if no error
    rcode: u8,
    /// number of questions in the question section
    pub qdcount: u16,
    /// number of records in answer section
    ancount: u16,
    /// number of records in authority section
    nscount: u16,
    /// number of records in additional section
    arcount: u16,
}

impl Header {
    pub fn serialize(&self) -> Vec<u8> {
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

    fn derserialize(bites: Vec<u8>) -> Result<Header> {
        if bites.len() != 12 {
            bail!("Header must be 12 bytes long");
        }
        let id = ((bites[0] as u16) << 8) | bites[1] as u16;
        let qr = bites[2] & 0b10000000 == 128;
        let opcode = (bites[2] & 0b01111000) >> 3;
        let aa = bites[2] & 0b00000100 == 4;
        let tc = bites[2] & 0b00000010 == 2;
        let rd = bites[2] & 0b00000001 == 1;
        let ra = bites[3] & 0b10000000 == 128;
        let z = (bites[3] & 0b01110000) >> 4;
        let rcode = bites[3] & 0b00001111;
        let qdcount = ((bites[4] as u16) << 8) | bites[5] as u16;
        let ancount = ((bites[6] as u16) << 8) | bites[7] as u16;
        let nscount = ((bites[8] as u16) << 8) | bites[9] as u16;
        let arcount = ((bites[10] as u16) << 8) | bites[11] as u16;
        return Ok(Header {
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
        });
    }
}

enum QType {
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

enum ResourceClass {
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
    tipe: QType,
    class: ResourceClass,
    name: Vec<String>,
}

impl Question{
    fn deserialize(bites: Vec<u8>) -> Result<Question> {
        let mut bite_iter = bites.into_iter().peekable();
        let mut name = vec![];
        loop{
            if let Some(bite) = bite_iter.next(){
                let label_len = bite.to_be();
                let label_bites:Vec<u8>  = bite_iter.by_ref().take(label_len as usize).collect();
                let label = String::from_utf8(label_bites)?;
                name.push(label);
                if bite_iter.peek() == Some(&0){
                    bite_iter.next();
                    break;
                }
            }else{
                bail!("Invalid input, couldn't read label length");
            }

        }
        let tipe_bite1 = bite_iter.next().context("Invalid input, couldn't read type value")?;
        let tipe_bite2 = bite_iter.next().context("Invalid input, couldn't read type value")?;
        let tipe_val = u16::from_be_bytes([tipe_bite1, tipe_bite2]);
        let tipe = QType::from_value(tipe_val)?;
        let class_bite1 = bite_iter.next().context("Invalid input, couldn't read class value")?;
        let class_bite2 = bite_iter.next().context("Invalid input, couldn't read class value")?;
        let class_val = u16::from_be_bytes([class_bite1, class_bite2]);
        let class = ResourceClass::from_value(class_val)?;
        Ok(Question{
            tipe,
            class,
            name,
        })
    }

    fn serialize(&self) -> Vec<u8> {
        let mut bites = vec![];
        for label in &self.name{
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
