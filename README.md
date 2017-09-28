# miaow
Mdns Improved Alternative Over Woof

## Description

miaow is a simple tool to share a file on a LAN. It is inspired by
[woof](http://www.home.unix-ag.org/simon/woof.html) but add mDNS feature. The
idea is to avoid having to share your ip address (it is annoying to spell the
digits of your ip address especially in a busy environment). Miaow broadcast
mDNS announcement based on your unix username.

The recipient just need to know your username to fetch your file!

The file transfer is done over http, so using a standard http client knowing
the ip address is still possible.

## Usage

To share a file, assuming your username is [hercule](https://en.wikipedia.org/wiki/Spiff_and_Hercules)

```
$ miaow share myfile
Now serving on http://192.168.1.42:4567/myfile as hercule
```

Another user on the LAN can fetch the file with:

```
$ miaow fetch hercule
Downloading http://192.168.1.42:4567/file
```

## Why?

I wrote this to learn the Rust language. So this program is just an excuse and
might never be finished :-)

I don't want to use "high level" crates and prefer rewriting stuff by myself
using the standard library (and some basic crates).

Contribution to make this code more rust idiomatic are more than welcome but I'm
not really interested in new feature (or even feature ;-)) right now.

## Status

NOT WORKING!

I want to focus on the client first. For now I have mDNS proof of concept.

The following steps are:

 * Pool mdns answer and retry: for now only the first response is read. We need
   to keep listening to response until a valid one is found (or timeout).
 * Client command line: pass username in command line and select the correct dns
   response
 * Server: start with a fake server based on avahi:
 `avahi-publish-service "miaow_1" _http._tcp 8080 file=path/to/file user=ced`
The http server can be woof itself + bash glue
 * It should be enough to test the client
 * Implement the server with Rust
