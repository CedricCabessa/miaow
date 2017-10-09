extern crate libmiaow;

use libmiaow::dnsresolv::DnsResolv;
use libmiaow::dnsparser::Resource;

use std::{thread, time};

fn main() {
    let dns = DnsResolv::new();

    loop {
        match dns.resolv_ptr("_http._tcp.local") {
            Ok(dnslist) => {
                let resource = Resource::parse_dns(dnslist).unwrap();
                println!("{:?}", resource);
            }
            Err(e) => println!("fail {}", e),
        };
        thread::sleep(time::Duration::from_secs(2));
    }
}
