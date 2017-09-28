use dnsresolv::DnsAnswer;
use dnsresolv::DnsType;
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
            match *answer.get_type() {
                DnsType::TXT => parse_txt(answer.get_data(), &mut user, &mut file),
                DnsType::A => parse_a(answer.get_data(), &mut ip),
                DnsType::SRV => parse_srv(answer.get_data(), &mut port),
                DnsType::PTR => continue,
                DnsType::UNKNOWN => continue,
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

fn parse_txt(mut data: Iter<u8>, user: &mut String, file: &mut String) {
    while let Some(size) = data.next() {
        let mut str = String::with_capacity(*size as usize);
        for _ in 0..*size {
            str.push(*data.next().unwrap() as char);
        }
        if str.starts_with("file=") {
            *file = str.split_off(5);
        } else if str.starts_with("user=") {
            *user = str.split_off(5);
        }
    }
}

fn parse_a(mut data: Iter<u8>, ip: &mut String) {
    write!(
        ip,
        "{}.{}.{}.{}",
        data.next().unwrap(),
        data.next().unwrap(),
        data.next().unwrap(),
        data.next().unwrap()
    ).expect("cannot write");

}

fn parse_srv(data: Iter<u8>, port: &mut u16) {
    let mut data = data.skip(4);
    *port = pop_u16(&mut data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tst_parse_srv() {
        let v: Vec<u8> = vec![0, 0, 0, 0, 0x1f, 0x90];
        let mut port = 0;
        parse_srv(v.iter(), &mut port);
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
        let mut file = String::new();
        let mut user = String::new();
        parse_txt(v.iter(), &mut user, &mut file);
        assert_eq!("path/to/file", file);
        assert_eq!("ced", user);
    }

    #[test]
    fn tst_parse_a() {
        let v: Vec<u8> = vec![0xc0, 0xa8, 0x01, 0x02];
        let mut ip = String::new();
        parse_a(v.iter(), &mut ip);
        assert_eq!("192.168.1.2", ip);
    }
}
