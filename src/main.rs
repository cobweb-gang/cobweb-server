use cobweb_server::vpn::{UdpVecCodec, EncryptedTun};
use cobweb_server::server::handshake;
use cobweb_server::en::{En, De};
use tokio_core::reactor::Core;
use tokio_core::net::{UdpSocket};
use futures::prelude::*;
use futures::stream::{SplitSink, SplitStream};
use futures::sink::With;
use futures::stream::Map;
use tun_tap::r#async::Async;
use miscreant::stream::{Encryptor, NONCE_SIZE};
use miscreant::Aes128SivAead;
use std::io::Result as HalfResult;
use clap::{Arg, App};

const NONCE_PREFIX: &[u8; NONCE_SIZE] = &[0u8; NONCE_SIZE];

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
    
    let loc_addr = "127.0.0.1:1337";
    let client_num = 0;
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let pass = matches.value_of("password").unwrap_or_else(|| {
        eprintln!("ERROR: You must provide a password");
        ::std::process::exit(1);
    });

    let sock = UdpSocket::bind(&loc_addr.parse().unwrap(), &handle).unwrap();

    loop {
        let (key, rem_addr) = handshake(&client_num, &loc_addr, &sock, pass).unwrap();
        client_num + 1;

        let ind_client_addr = format!("127.0.0.1:{}", 1337 + client_num);
        let mut one_time_en: Encryptor<Aes128SivAead> = Encryptor::new(key.as_slice(), NONCE_PREFIX);
        let message = one_time_en.seal_next(&[], ind_client_addr.as_bytes());
        
        let ind_client_sock = UdpSocket::bind(&ind_client_addr.parse().unwrap(), &handle).unwrap();
        sock.send(message.as_slice()).unwrap();

        let (udp_sink, udp_stream) = ind_client_sock.framed(UdpVecCodec::new(rem_addr))
            .split();

        let tun = EncryptedTun::<With<SplitSink<Async>, Vec<u8>, De, HalfResult<Vec<u8>>>, Map<SplitStream<Async>, En>>::new(&key, &handle);

        let (tun_sink, tun_stream) = tun.unwrap().split();

        let sender = tun_stream.forward(udp_sink);
        let receiver = udp_stream.forward(tun_sink);
        core.run(sender.join(receiver))
            .unwrap();
    }
}
