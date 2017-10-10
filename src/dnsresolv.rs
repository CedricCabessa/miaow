use std::io::{Cursor, BufRead};
use std::net::Ipv4Addr;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time;
use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};
use rand::random;
use mio::{Events, Poll, PollOpt, Ready, Token};
use mio::net::UdpSocket;

use DnsError;

/// Dns resolver: send dns request
pub struct DnsResolv {
    id: u16,
}

impl DnsResolv {
    pub fn new() -> DnsResolv {
        DnsResolv { id: random() }
    }

    /// resolve a dns query using a PTR request.
    ///
    /// This assume all informations are available using only one PTR request.
    /// RFC6763 12.1: the server should include the SRV / TXT / A data.
    pub fn resolv_ptr(&self, query: &str) -> Result<Vec<DnsAnswer>, DnsError> {
        let query_buffer = self.create_query_buffer(query)?;

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        let socket = UdpSocket::bind(&addr)?;

        socket
            .join_multicast_v4(&Ipv4Addr::new(224, 0, 0, 251), &Ipv4Addr::new(0, 0, 0, 0))?;

        socket
            .send_to(query_buffer.into_inner().as_slice(),
                     &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
                                      5353))?;

        let mut answer_buffer: [u8; 512] = [0; 512];

        let poll = Poll::new()?;
        poll.register(&socket, Token(0), Ready::readable(), PollOpt::edge())?;
        let mut events = Events::with_capacity(1024);

        let timeout = time::Duration::from_millis(100);
        let mut dnsanswers = Vec::new();

        loop {
            let nbevent = poll.poll(&mut events, Some(timeout))?;
            if nbevent == 0 {
                break
            }
            for _ in &events {
                // spurious events?
                socket.recv(&mut answer_buffer)?;
                let mut dnsanswer = self.parse_answers(Cursor::new(answer_buffer.to_vec()))?;
                dnsanswers.append(&mut dnsanswer);
            }
        }
        Ok(dnsanswers)
    }

    fn create_query_buffer(&self, host: &str) -> Result<Cursor<Vec<u8>>, DnsError> {
        let mut buffer = Cursor::new(Vec::new());

        buffer.write_u16::<BigEndian>(self.id)?;
        buffer.write_u16::<BigEndian>(1 << 8)?;  // option: recursive
        buffer.write_u16::<BigEndian>(1)?; // qcount
        buffer.write_u16::<BigEndian>(0)?; // ancount
        buffer.write_u16::<BigEndian>(0)?; // nscount
        buffer.write_u16::<BigEndian>(0)?; // arcount

        for label in host.split(".") {
            buffer.write_u8(label.len() as u8)?;
            for b in label.bytes() {
                buffer.write_u8(b)?;
            }
        }

        buffer.write_u8(0)?;

        buffer.write_u16::<BigEndian>(12)?; // PTR
        buffer.write_u16::<BigEndian>(1)?; // IN

        Ok(buffer)
    }

    fn parse_answers<T: BufRead>(&self, mut answer_buffer: T) -> Result<Vec<DnsAnswer>, DnsError> {
        // TODO check header (tc bit, ...)
        let id = answer_buffer.read_u16::<BigEndian>()?;
        if id != self.id {
            return Err(DnsError::InvalidFormat(String::from("wrong id")));
        }
        answer_buffer.read_u16::<BigEndian>()?; //skip FLAGS
        answer_buffer.read_u16::<BigEndian>()?; //skip QDCOUNT

        let ancount = answer_buffer.read_u16::<BigEndian>()?;

        let mut answers: Vec<DnsAnswer> = Vec::with_capacity(ancount as usize);

        answer_buffer.read_u16::<BigEndian>()?; //skip NSCOUNT
        answer_buffer.read_u16::<BigEndian>()?; //skip ARCOUNT

        answer_buffer.read_until(0, &mut Vec::new())?; // skip QNAME
        answer_buffer.read_u16::<BigEndian>()?; //skip QTYPE
        answer_buffer.read_u16::<BigEndian>()?; //skip QCLASS

        for _ in 0..ancount {
            let dns_answer = match create_dnsanswer(&mut answer_buffer) {
                Ok(a) => a,
                Err(e) => return Err(e),
            };
            answers.push(dns_answer);
        }
        Ok(answers)
    }
}

fn create_dnsanswer<T: BufRead>(answer_buffer: &mut T) -> Result<DnsAnswer, DnsError> {
    let name = answer_buffer.read_u8()?;
    if name != 0xc0 {
        return Err(DnsError::InvalidFormat(
            String::from("parser doesn't support non pointer value")));
    }

    answer_buffer.read_u8()?; // skip name last byte
    let dnstype = answer_buffer.read_u16::<BigEndian>()?;

    answer_buffer.read_u16::<BigEndian>()?; // skip CLASS
    answer_buffer.read_u32::<BigEndian>()?; // skip TTL

    let rdlength = answer_buffer.read_u16::<BigEndian>()?;
    let mut dnsdata: Vec<u8> = Vec::with_capacity(rdlength as usize);
    for _ in 0..rdlength {
        let v = answer_buffer.read_u8()?;
        dnsdata.push(v);
    }

    Ok(DnsAnswer::new(dnstype, dnsdata))
}

/// dns result. data can be parsed acording to dns_type.
#[derive(Debug)]
#[derive(PartialEq)]
pub enum DnsAnswer {
    UNKNOWN(Vec<u8>),
    PTR(Vec<u8>),
    TXT(Vec<u8>),
    A(Vec<u8>),
    SRV(Vec<u8>),
}

impl DnsAnswer {
    fn new(idns_type: u16, data: Vec<u8>) -> DnsAnswer {
        match idns_type {
            1 => DnsAnswer::A(data),
            12 => DnsAnswer::PTR(data),
            16 => DnsAnswer::TXT(data),
            33 => DnsAnswer::SRV(data),
            _ => DnsAnswer::UNKNOWN(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tst_parseanswer() {
        let resolv = DnsResolv { id: 42 };
        let v: Vec<u8> = vec![
            0x00,
            0x2a,
            0x84,
            0x00,
            0x00,
            0x01,
            0x00,
            0x05,
            0x00,
            0x00,
            0x00,
            0x00,
            0x05,
            0x5f,
            0x68,
            0x74,
            0x74,
            0x70,
            0x04,
            0x5f,
            0x74,
            0x63,
            0x70,
            0x05,
            0x6c,
            0x6f,
            0x63,
            0x61,
            0x6c,
            0x00,
            0x00,
            0x0c,
            0x00,
            0x01,
            0xc0,
            0x0c,
            0x00,
            0x0c,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x0a,
            0x00,
            0x0a,
            0x07,
            0x6d,
            0x69,
            0x61,
            0x6f,
            0x77,
            0x5f,
            0x31,
            0xc0,
            0x0c,
            0xc0,
            0x2e,
            0x00,
            0x10,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x0a,
            0x00,
            0x1b,
            0x11,
            0x66,
            0x69,
            0x6c,
            0x65,
            0x3d,
            0x70,
            0x61,
            0x74,
            0x68,
            0x2f,
            0x74,
            0x6f,
            0x2f,
            0x66,
            0x69,
            0x6c,
            0x65,
            0x08,
            0x75,
            0x73,
            0x65,
            0x72,
            0x3d,
            0x63,
            0x65,
            0x64,
            0xc0,
            0x2e,
            0x00,
            0x21,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x0a,
            0x00,
            0x0e,
            0x00,
            0x00,
            0x00,
            0x00,
            0x1f,
            0x90,
            0x05,
            0x6c,
            0x69,
            0x6e,
            0x75,
            0x78,
            0xc0,
            0x17,
            0xc0,
            0x71,
            0x00,
            0x1c,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x0a,
            0x00,
            0x10,
            0xfe,
            0x80,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x47,
            0x4d,
            0xd7,
            0x46,
            0x54,
            0x16,
            0xee,
            0xbb,
            0xc0,
            0x71,
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x0a,
            0x00,
            0x04,
            0x0a,
            0x74,
            0x00,
            0x19,
        ];
        let answers = resolv.parse_answers(Cursor::new(v)).unwrap();
        assert_eq!(5, answers.len());
        assert_eq!(
            1,
            answers
                .iter()
                .filter(|x| match **x {
                    DnsAnswer::A(_) => true,
                    _ => false,
                })
                .count()
        );
        assert_eq!(
            1,
            answers
                .iter()
                .filter(|x| match **x {
                    DnsAnswer::UNKNOWN(_) => true,
                    _ => false,
                })
                .count()
        ); //AAAA
        assert_eq!(
            1,
            answers
                .iter()
                .filter(|x| match **x {
                    DnsAnswer::SRV(_) => true,
                    _ => false,
                })
                .count()
        );
        assert_eq!(
            1,
            answers
                .iter()
                .filter(|x| match **x {
                    DnsAnswer::TXT(_) => true,
                    _ => false,
                })
                .count()
        );
        assert_eq!(
            1,
            answers
                .iter()
                .filter(|x| match **x {
                    DnsAnswer::PTR(_) => true,
                    _ => false,
                })
                .count()
        );
    }
}
