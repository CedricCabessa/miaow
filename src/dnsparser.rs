use dnsresolv::DnsAnswer;
use std::fmt::Write;
use std::io::{Cursor, BufRead};
use byteorder::{BigEndian, ReadBytesExt};

use DnsError;

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
    pub fn parse_dns(dns_answers: Vec<DnsAnswer>) -> Result<Resource, DnsError> {
        let mut ip = String::new();
        let mut user = String::new();
        let mut file = String::new();
        let mut port = 0;

        for answer in dns_answers {
            match answer {
                DnsAnswer::TXT(data) => {
                    let (f, u) = parse_txt(Cursor::new(data))?;
                    file = f;
                    user = u;
                },
                DnsAnswer::A(data) => {
                    ip = parse_a(Cursor::new(data))?;
                }
                DnsAnswer::SRV(data) => {
                    port = parse_srv(Cursor::new(data))?;
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

fn parse_txt<T: BufRead>(mut data: T) -> Result<(String, String), DnsError> {
    let mut file = String::new();
    let mut user = String::new();

    while let Ok(size) = data.read_u8() {
        let mut str = String::with_capacity(size as usize);
        for _ in 0..size {
            str.push(data.read_u8()? as char);
        }
        if str.starts_with("file=") {
            file = str.split_off(5);
        } else if str.starts_with("user=") {
            user = str.split_off(5);
        }
    }
    Ok((file, user))
}

fn parse_a<T: BufRead>(mut data: T) -> Result<String, DnsError> {
    let mut ip = String::new();
    write!(
        ip,
        "{}.{}.{}.{}",
        data.read_u8()?,
        data.read_u8()?,
        data.read_u8()?,
        data.read_u8()?,
    ).expect("wrong format");
    Ok(ip)
}

fn parse_srv<T: BufRead>(mut data: T) -> Result<u16, DnsError> {
    data.read_u32::<BigEndian>()?;
    Ok(data.read_u16::<BigEndian>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tst_parse_srv() {
        let v: Vec<u8> = vec![0, 0, 0, 0, 0x1f, 0x90];
        let port = parse_srv(Cursor::new(v)).unwrap();
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
        let (file, user) = parse_txt(Cursor::new(v)).unwrap();
        assert_eq!("path/to/file", file);
        assert_eq!("ced", user);
    }

    #[test]
    fn tst_parse_a() {
        let v: Vec<u8> = vec![0xc0, 0xa8, 0x01, 0x02];
        let ip = parse_a(Cursor::new(v)).unwrap();
        assert_eq!("192.168.1.2", ip);
    }
}
