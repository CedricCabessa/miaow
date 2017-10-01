use std::net::UdpSocket;
use std::net::Ipv4Addr;
use std::net::IpAddr;
use std::net::SocketAddr;
use rand::random;

use pop_u16;
use pop_u8;
use push_u16;
use push_u8;
use push_str;

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
    /// It is true while testing with avahi, other implementation might require
    /// multiple dns requests.
    pub fn resolv_ptr(self, query: &str) -> Result<Vec<DnsAnswer>, &'static str> {
        let buffer = self.create_buffer(query);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        let socket = UdpSocket::bind(addr).expect("couldn't bind");
        socket
            .join_multicast_v4(&Ipv4Addr::new(224, 0, 0, 251), &Ipv4Addr::new(0, 0, 0, 0))
            .unwrap();

        socket
            .send_to(buffer.as_slice(), "224.0.0.251:5353")
            .expect("cannot send");

        let mut answer_buffer: [u8; 512] = [0; 512];
        //TODO: multiple reply / timeout
        socket.recv(&mut answer_buffer).expect("read data");
        self.parse_answers(&answer_buffer)
    }

    fn create_buffer(&self, host: &str) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();

        push_u16(&mut buffer, self.id);
        push_u16(&mut buffer, 1 << 8); // option: recursive
        push_u16(&mut buffer, 1); // qcount
        push_u16(&mut buffer, 0); // ancount
        push_u16(&mut buffer, 0); // nscount
        push_u16(&mut buffer, 0); // arcount

        for label in host.split(".") {
            push_u8(&mut buffer, label.len() as u8);
            push_str(&mut buffer, label);
        }

        push_u8(&mut buffer, 0);

        push_u16(&mut buffer, 12); // PTR
        push_u16(&mut buffer, 1); // IN

        buffer
    }

    fn parse_answers(&self, answer_buffer: &[u8]) -> Result<Vec<DnsAnswer>, &'static str> {
        // TODO check header (tc bit, ...)
        let mut iter = answer_buffer.iter();
        let id = pop_u16(&mut iter);
        if id != self.id {
            return Err("wrong id");
        }

        let mut iter = iter.skip(4); //skip FLAGS, QDCOUNT
        let ancount = pop_u16(&mut iter);
        let mut answers: Vec<DnsAnswer> = Vec::with_capacity(ancount as usize);

        let mut iter = iter.skip(4); //skip NSCOUNT, ARCOUNT
        iter.find(|&&x| x == 0).expect("malformed packet"); // skip QNAME
        let mut iter = iter.skip(4); // skip QTYPE / QCLASS

        for _ in 0..ancount {
            let dns_answer = match create_dnsanswer(&mut iter) {
                Ok(a) => a,
                Err(e) => return Err(e),
            };
            answers.push(dns_answer);
        }

        Ok(answers)
    }
}

fn create_dnsanswer<'a, T>(iter: &mut T) -> Result<DnsAnswer, &'static str>
where
    T: Iterator<Item = &'a u8>,
{

    let name = pop_u8(iter);
    if name != 0xc0 {
        return Err("parser doesn't support non pointer value");
    }
    let mut iter = iter.skip(1); // skip name last byte
    let dnstype = pop_u16(&mut iter);

    let mut iter = iter.skip(6); // skip CLASS / TTL

    let rdlength = pop_u16(&mut iter);
    let mut dnsdata: Vec<u8> = Vec::with_capacity(rdlength as usize);
    for _ in 0..rdlength {
        dnsdata.push(*iter.next().unwrap());
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
        let answers = resolv.parse_answers(&v).unwrap();
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
