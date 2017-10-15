extern crate byteorder;
extern crate rand;
extern crate mio;
use std::io;
use std::fmt;

pub mod dnsresolv;
pub mod dnsparser;
pub mod httpclient;

#[derive(Debug)]
pub enum DnsError {
    Io(io::Error),
    InvalidFormat(String),
    InvalidResource(),
}

impl From<io::Error> for DnsError {
    fn from(err: io::Error) -> DnsError {
        DnsError::Io(err)
    }
}

impl From<String> for DnsError {
    fn from(err: String) -> DnsError {
        DnsError::InvalidFormat(err)
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DnsError::Io(ref err) => write!(f, "error: {}", err),
            DnsError::InvalidFormat(ref err) => write!(f, "Invalid format: {}", err),
            DnsError::InvalidResource() => write!(f, "Invalid resource"),
        }
    }
}
