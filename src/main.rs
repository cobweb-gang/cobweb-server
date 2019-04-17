use cobweb_server::vpn::{TcpVecCodec, EncryptedTun};
use cobweb_server::server::handshake;
use cobweb_server::en::{En, De};
use tokio_core::reactor::Core;
use tokio_core::net::TcpListener;
use tokio_io::AsyncRead;
use futures::prelude::*;
use futures::stream::{SplitSink, SplitStream};
use futures::sink::With;
use futures::stream::Map;
use tun_tap::r#async::Async;
use clap::{Arg, App};
use std::io::Result as HalfResult;
use std::io::Write;

fn main() {
    let matches = App::new("Cobweb")
        .version("0.1.0")
        .author("David Bernado <dbernado@protonmail.com>")
        .about("Server software for the Cobweb VPN protocol")
        .arg(Arg::with_name("password")
             .short("p")
             .long("password")
             .value_name("FILE")
             .help("Sets the password for your server")
             .takes_value(true))
        .get_matches();
    
    let mut loc_addr = "0.0.0.0:1337".parse().unwrap();
    let client_num = 1;
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let pass = matches.value_of("password").unwrap_or_else(|| {
        eprintln!("ERROR: You must provide a password");
        ::std::process::exit(1);
    });

    let init_sock = TcpListener::bind(&loc_addr, &handle).unwrap();

    let future = init_sock.incoming().for_each(move |(mut stream, _rem_addr)| {
        let port: u16 = 1337 + client_num;

        stream.write(&port.to_be_bytes()).unwrap();

        let key = handshake(&client_num, &"0.0.0.0:1337", &stream, pass).unwrap();
        client_num + 1;
        
        loc_addr.set_port(port);
        let (ind_sock, _addr) = TcpListener::bind(&loc_addr, &handle).unwrap()
            .accept()
            .unwrap();
    
        let (tcp_sink, tcp_stream) = ind_sock.framed(TcpVecCodec)
            .split();
    
        let tun = EncryptedTun::<With<SplitSink<Async>, Vec<u8>, De, HalfResult<Vec<u8>>>, Map<SplitStream<Async>, En>>::new(&handle).unwrap().encrypt(&key);

        let (tun_sink, tun_stream) = tun.unwrap().split();

        let sender = tun_stream.forward(tcp_sink);
        let receiver = tcp_stream.forward(tun_sink);
        core.run(sender.join(receiver))
            .unwrap();

        Ok(())
    });

    let mut core1 = Core::new().unwrap();
    core1.run(future).unwrap();
}
