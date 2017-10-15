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

Alpha

Client is basically working, need more error check, retry, etc but you can fetch
a file.

The server is mocked in bash in [server/miaow](server/miaow).

You need `avahi-publish-service` and `woof` in the `PATH`
