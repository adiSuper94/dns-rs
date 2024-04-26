use std::{
    collections::HashMap,
    net::{SocketAddr, UdpSocket},
};

use crate::message::{Answer, Message, QType, ResourceClass};

pub struct DnsServer {
    resolver: Option<SocketAddr>,
    source_map: HashMap<u16, (u16, SocketAddr)>,
    orig_messages: HashMap<u16, Message>,
}

impl DnsServer {
    pub fn new(resolver: Option<String>) -> Self {
        if resolver.is_none() {
            return DnsServer {
                resolver: None,
                source_map: HashMap::new(),
                orig_messages: HashMap::new(),
            };
        }
        let resolver = resolver.unwrap();
        let resolver: SocketAddr = resolver.parse().unwrap();
        DnsServer {
            resolver: Some(resolver),
            source_map: HashMap::new(),
            orig_messages: HashMap::new(),
        }
    }

    pub fn process(&mut self, mut m: Message, source: SocketAddr, socket: &UdpSocket) {
        if self.resolver.is_none() {
            let m = Self::update_message(m);
            socket.send_to(&m.to_bytes(), source).unwrap();
            return;
        }
        if m.header.qr {
            self.source_map
                .entry(m.header.id)
                .and_modify(|(cnt, _addr)| *cnt -= 1);
            self.orig_messages.entry(m.header.id).and_modify(|msg| {
                msg.header.ancount += 1;
                msg.header.qr = true;
                msg.header.rcode = 4;
                msg.answers.extend(m.answers);
            });
            if self.source_map.get(&m.header.id).unwrap().0 <= 0 {
                let (_, source) = self.source_map.get(&m.header.id).unwrap();
                if let Some(mut m) = self.orig_messages.remove(&m.header.id) {
                    m.header.ancount = m.answers.len() as u16;
                    socket.send_to(&m.to_bytes(), source).unwrap();
                }
                self.source_map.remove(&m.header.id);
            }
            return;
        }
        let resolver = self.resolver.as_ref().unwrap();
        self.source_map
            .insert(m.header.id, (m.questions.len() as u16, source));
        for q in m.questions.iter() {
            let mut m2 = m.clone();
            m2.header.qdcount = 1;
            m2.questions = vec![q.clone()];
            socket.send_to(&m2.to_bytes(), resolver).unwrap();
        }
        m.answers.clear();
        self.orig_messages.insert(m.header.id, m);
    }

    pub fn resolver(&self) -> String {
        if let Some(resolver) = &self.resolver {
            resolver.to_string()
        } else {
            "".to_string()
        }
    }

    fn update_message(mut m: Message) -> Message {
        m.header.qr = true;
        m.header.aa = false;
        m.header.tc = false;
        m.header.ra = false;
        m.header.z = 0;
        m.header.qdcount = m.questions.len() as u16;
        m.header.ancount = m.questions.len() as u16;
        m.answers = Vec::new();
        for q in m.questions.iter_mut() {
            q.tipe = QType::A;
            q.class = ResourceClass::IN;
            let ans = Answer {
                name: q.name.clone(),
                tipe: QType::A,
                class: ResourceClass::IN,
                ttl: 60,
                rdlength: 4,
                rdata: vec![127, 0, 0, 1],
            };
            m.answers.push(ans);
        }
        m
    }
}
