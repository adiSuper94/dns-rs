use anyhow::{bail, Result};

pub struct Message {
    pub header: Header,
}

impl Message {
    pub fn serialize(&self) -> Vec<u8> {
        let bites = self.header.serialize_self();
        return bites;
    }

    pub fn deserialize(bites: [u8; 512]) -> Result<Message> {
        let header_bites = bites[0..12].to_vec();
        let header = Header::derserialize(header_bites)?;
        return Ok(Message { header });
    }
}

pub struct Header {
    id: u16,
    /// query or response: 0 for question, 1 for reply
    qr: bool,
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
    qdcount: u16,
    /// number of records in answer section
    ancount: u16,
    /// number of records in authority section
    nscount: u16,
    /// number of records in additional section
    arcount: u16,
}

impl Header {
    pub fn serialize_self(&self) -> Vec<u8> {
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

    pub fn set_qr(&mut self, qr: bool) {
        self.qr = qr;
    }

}
