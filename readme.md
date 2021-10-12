# Trojan-Oxide

A Rust implementation of Trojan with QUIC tunnel, Lite-TLS and more.

## Overview

1. Full support for the original [Trojan](https://github.com/trojan-gfw/trojan ) Protocol, including TCP and UDP traffic.
2. Pure Rust implementation with no comprimise on security and speed.
   * Highly efficient [Tokio](https://github.com/tokio-rs/tokio)-based async network io.
   * Minimized memory consumption.
   * Predictable performance with no runtime garbage collector.
   * Poll based UDP Traffic.
3. [QUIC](https://en.wikipedia.org/wiki/QUIC) tunnel. The stealth Trojan implementation is still undetectable in the HTTP/3 era.
4. [Lite-TLS](https://github.com/3andne/trojan-oxide/wiki/The-Speed-of-Lite). Avoid redundant encrpytion with TLS traffics without modifying the underlying TLS library. We do things in the Trojan way, i.e., we imitate rather than create.
5. [Zero-Copy](https://kernel.dk/io_uring.pdf?source=techstories.org) (Linux Kernel >= 5.8 is required). With Lite-TLS enabled, we can achieve maximum efficiency on both the client and server sides. Up to [60% improvement](https://github.com/frevib/io_uring-echo-server/blob/master/benchmarks/benchmarks.md) is observed in a TCP echo server based on io-uring.

## License

[GPL-3](https://github.com/3andne/trojan-oxide/blob/main/LICENSE)

## Examples

### Install Rust

Please follow the [instructions](https://www.rust-lang.org/tools/install).

### Build Trojan-Oxide From Source

```
git clone https://github.com/3andne/trojan-oxide.git && cd ./trojan-oxide
cargo build --release
```

The executable binary file is  `./target/release/trojan-oxide`.

#### Build Selected Features

You can select features according to your needs; the default configuration builds both the server and client.

##### Server Only

```
cargo build --release --features server_full
```

##### Client Only

```
cargo build --release --features client_full
```

##### Zero Copy Feature

This feature is disabled by default since it only works on Linux with a kernel >= 5.8. The following command will build this feature.

```
cargo build --release --features client_full,zio
cargo build --release --features server_full,zio
```

### Run Server

Suppose you have a server `your.website.com`.

* Your TLS certificate is in "/path/to/cert/fullchain.cert".

* Your TLS private key is in "/path/to/key/private.key".

* You want the server to listen on port `443`, and re-direct unauthenticated traffics to `80`.
* You set password to `your_password`. **If your password contains '$', please write it as '\\$'.**

Then you should start the server by:

```
./target/release/trojan-oxide -s -w "your_password" -k "/path/to/key/private.key" -c "/path/to/cert/fullchain.cert" -u "your.website.com" -x 443 -f 80
```

Note that rustls (the underlying tls library) **doesn't support ECC keys** as of this moment.  Please Follow the [instructions](https://github.com/rustls/rustls/issues/767) if you have a pair of ECC keys.

### Run Client

If you have a `tcp-tls` trojan service on `your.website.com:443` with the password `your_password`. You can start your client by:

```
./target/release/trojan-oxide -w "your_password" -u you.website.com -x 443 -m t
```

* the default tunnel is TCP-TLS

  * use `-m q` if you want to use the QUIC tunnel
  * use `-m l` if you want to use the Lite-TLS tunnel

* you can also specify your server ip by:

  ```
  ./target/release/trojan-oxide -w "your_password" -u you.website.com -d 114.51.4.191 -x 443 -m t
  ```

* **The default http and socks5 port is `8888 ` and `8889` respectively. Please specify them by `-h` and `-5`.**

### Run Zero Copy Endpoints

Note that this feature only works when Linux kernel >= 5.8. Please build the client/server with `zio` feature first.

Then start the client in Lite-TLS mode.

```
./target/release/trojan-oxide -w "your_password" -u you.website.com -d 114.51.4.191 -x 443 -m l
```

You don't need to configure the server.

### Manual

```
./target/release/trojan-oxide --help
```

```
USAGE:
    trojan-oxide [FLAGS] [OPTIONS] --password <password> [remote-socket-addr]

FLAGS:
        --help       
            Prints help information

    -s, --server     
            whether to start as server

    -V, --version    
            Prints version information


OPTIONS:
        --ca <ca>                              
            

    -c, --cert <cert>                          
            TLS certificate in PEM format

    -m, --connection-mode <connection-mode>    
            Connetion Mode:
            
            - t (for tcp-tls)
            
            - q (for quic)
            
            - l (for lite-tls) [default: t]
    -f, --fallback-port <fallback-port>        
            port to re-direct unauthenticated connections [default: 0]

    -k, --key <key>                            
            TLS private key in PEM format

    -h, --http_port <local-http-addr>          
            client http proxy port [default: 8888]

    -5, --socks5_port <local-socks5-addr>      
            client socks5 proxy port [default: 8889]

    -l, --log-level <log-level>                
            Log level (from least to most verbose):
            
            error < warn < info < debug < trace [default: info]
    -w, --password <password>                  
            the password to authenticate connections

    -u, --server-hostname <server-hostname>    
            Server Name Indication (sni), or Hostname [default: localhost]

    -d, --server-ip <server-ip>                
            server ip address [default: ]

    -x, --server-port <server-port>            
            server proxy port [default: 443]
```
