extern crate byteorder;
extern crate rand;

use byteorder::{BigEndian, ByteOrder};

fn push_u16(buffer: &mut Vec<u8>, value: u16) {
    let mut tmp: [u8; 2] = [0; 2];
    BigEndian::write_u16(&mut tmp, value);
    buffer.push(tmp[0]);
    buffer.push(tmp[1]);
}

fn push_u8(buffer: &mut Vec<u8>, value: u8) {
    buffer.push(value);
}

fn push_str(buffer: &mut Vec<u8>, value: &str) {
    for b in value.bytes() {
        buffer.push(b);
    }
}

fn pop_u16<'a, T>(iter: &mut T) -> u16
where
    T: Iterator<Item = &'a u8>,
{
    //FIXME: useless lifetime??
    let mut tmp: [u8; 2] = [0; 2];
    tmp[0] = *iter.next().unwrap();
    tmp[1] = *iter.next().unwrap();
    BigEndian::read_u16(&tmp)
}

fn pop_u8<'a, T>(iter: &mut T) -> u8
where
    T: Iterator<Item = &'a u8>,
{
    //FIXME: useless lifetime??
    *iter.next().unwrap()
}


pub mod dnsresolv;
pub mod dnsparser;
