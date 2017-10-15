use std::io::{BufRead, BufReader, Result, Write};
use std::fmt::Write as FmtWrite;
use std::net::{TcpStream, SocketAddr};
use std::fs::File;

pub fn httpclient(host: &str, port: u16, file: &str) -> Result<()> {
    let mut stream = TcpStream::connect(SocketAddr::new(host.parse().unwrap(),
                                                        port))?;
    let mut query = String::new();
    write!(query,
           "GET /{} HTTP/1.1\r\nHost: {}\r\nUser-Agent: miaow\r\nAccept: */*\r\n\r\n",
           file, host).unwrap();
    stream.write(query.as_bytes())?;

    let mut reader = BufReader::with_capacity(1024 * 1024, stream);
    let mut writer = File::create(file)?;

    loop {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        if header == "\r\n" {
            break;
        }
    }

    loop {
        let length = {
            let buffer = reader.fill_buf()?;
            writer.write_all(buffer)?;
            buffer.len()
        };
        if length == 0 {
            break;
        }
        reader.consume(length);
    }

    Ok(())
}
