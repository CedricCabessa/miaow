extern crate libmiaow;
extern crate docopt;

use libmiaow::dnsresolv::DnsResolv;
use libmiaow::dnsparser::Resource;
use libmiaow::httpclient::httpclient;
use libmiaow::DnsError;

use std::{thread, time, process};

use docopt::Docopt;

const MAX_TRY: u32 = 5;
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
        process::exit(match fetch(name) {
            Ok(_) => 0,
            Err(_) => 1,
        });
    } else if args.get_bool("share") {
        println!("share is not yet implemented");
    }
}

fn fetch(name :&str) -> Result<(), ()> {
    let dns = DnsResolv::new();
    let mut nb_try = 0;
    loop {
        println!("Waiting for {}...", name);
        match dns.resolv_ptr("_http._tcp.local") {
            Ok(dnslist) => {
                match Resource::parse_dns(dnslist) {
                    Ok(resource) => {
                        if resource.user() == name {
                            match httpclient(resource.host(),
                                             resource.port(),
                                             resource.file()) {
                                Ok(_) => {
                                    println!("write {}", resource.file());
                                    return Ok(());
                                },
                                Err(_) => return Err(()),
                            }
                        }
                    },
                    Err(err) => match err {
                        DnsError::InvalidResource() => continue,
                        err => println!("{:?}", err),
                    }
                }
            }
            Err(e) => println!("fail {}", e),
        };
        thread::sleep(time::Duration::from_secs(2));
        nb_try += 1;
        if nb_try > MAX_TRY {
            println!("{} is not found", name);
            return Err(());
        }
    }
}
