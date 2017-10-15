extern crate libmiaow;
extern crate docopt;

use libmiaow::dnsresolv::DnsResolv;
use libmiaow::dnsparser::Resource;
use libmiaow::DnsError;

use std::{thread, time};

use docopt::Docopt;

const USAGE: &'static str = "
miaow

Usage:
  miaow share <file>
  miaow fetch <name>

Options:
  -h --help    Show this screen
  --version    Show version
";


fn main() {
    let args = Docopt::new(USAGE)
        .and_then(|d| d.argv(std::env::args().into_iter()).parse())
        .unwrap_or_else(|e| e.exit());

    if args.get_bool("fetch") {
        let name = args.get_str("<name>");
        fetch(name);
    } else if args.get_bool("share") {
        println!("share is not yet implemented");
    }
}

fn fetch(name :&str) {
    let dns = DnsResolv::new();
    loop {
        match dns.resolv_ptr("_http._tcp.local") {
            Ok(dnslist) => {
                match Resource::parse_dns(dnslist) {
                    Ok(resource) => {
                        if resource.user() == name {
                            println!("{:?}", resource);
                        }
                    },
                    Err(err) => match err {
                        DnsError::InvalidResource() => { println!("invalid"); continue},
                        err => println!("{:?}", err),
                    }
                }
            }
            Err(e) => println!("fail {}", e),
        };
        thread::sleep(time::Duration::from_secs(2));
    }
}
