use dnsresolv::DnsAnswer;
use std::fmt::Write;
use std::slice::Iter;

use pop_u16;

#[derive(Debug)]
/// Informations needed to download a file
pub struct Resource {
    ip: String,
    port: u16,
    user: String,
    file: String,
}

impl Resource {
    /// given a list of dns answer (PTR request) created by DnsResolv::resolv_ptr(),
    /// create a Resource object to download the file
    pub fn parse_dns(dns_answers: Vec<DnsAnswer>) -> Result<Resource, &'static str> {
        let mut ip = String::new();
        let mut user = String::new();
        let mut file = String::new();
        let mut port = 0;

        for answer in dns_answers {
            match answer {
                DnsAnswer::TXT(data) => {
                    let (f, u) = parse_txt(data.iter());
                    file = f;
                    user = u;
                },
                DnsAnswer::A(data) => {
                    ip = parse_a(Cursor::new(data))?;
                }
                DnsAnswer::SRV(data) => {
                    port = parse_srv(data.iter());
                }
                DnsAnswer::PTR(_) => continue,
                DnsAnswer::UNKNOWN(_) => continue,
            };
        }
        let resource = Resource {
            ip,
            port,
            user,
            file,
        };
        Ok(resource)
    }
}

fn parse_txt(mut data: Iter<u8>) -> (String, String) {
    let mut file = String::new();
    let mut user = String::new();

    while let Some(size) = data.next() {
        let mut str = String::with_capacity(*size as usize);
        for _ in 0..*size {
            str.push(*data.next().unwrap() as char);
        }
        if str.starts_with("file=") {
            file = str.split_off(5);
        } else if str.starts_with("user=") {
            user = str.split_off(5);
        }
    }
    (file, user)
}

fn parse_a(mut data: Iter<u8>) -> String {
    let mut ip = String::new();
    write!(
        ip,
        "{}.{}.{}.{}",
        data.next().unwrap(),
        data.next().unwrap(),
        data.next().unwrap(),
        data.next().unwrap()
    ).expect("cannot write");
    ip
}

fn parse_srv(data: Iter<u8>) -> u16 {
    let port;
    let mut data = data.skip(4);
    port = pop_u16(&mut data);
    port
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tst_parse_srv() {
        let v: Vec<u8> = vec![0, 0, 0, 0, 0x1f, 0x90];
        let port = parse_srv(v.iter());
        assert_eq!(8080, port);
    }

    #[test]
    fn tst_parse_txt() {
        let v: Vec<u8> = vec![
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
        ];
        let (file, user) = parse_txt(v.iter());
        assert_eq!("path/to/file", file);
        assert_eq!("ced", user);
    }

    #[test]
    fn tst_parse_a() {
        let v: Vec<u8> = vec![0xc0, 0xa8, 0x01, 0x02];
        let ip = parse_a(v.iter());
        assert_eq!("192.168.1.2", ip);
    }
}
