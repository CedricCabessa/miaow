extern crate libmiaow;

use libmiaow::dnsresolv::DnsResolv;
use libmiaow::dnsparser::Resource;

fn main() {
    let dns = DnsResolv::new();
    match dns.resolv_ptr("_http._tcp.local") {
        Ok(dnslist) => {
            let resource = Resource::parse_dns(dnslist).unwrap();
            println!("{:?}", resource);
        }
        Err(e) => println!("fail {}", e),
    };
}
