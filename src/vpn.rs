use crate::en::{En, De};
use std::io::Result;
use keybob::Key;
use tun_tap::{Iface, Mode};
use tun_tap::r#async::Async;
use std::process::Command;
use tokio_core::reactor::Handle;
use tokio_codec::{Decoder, Encoder};
use futures::prelude::*;
use futures::stream::{SplitSink, SplitStream};
use futures::sink::With;
use futures::stream::Map;
use bytes::BytesMut;

fn cmd(cmd: &str, args: &[&str]) {
    let ecode = Command::new("ip")
        .args(args)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    assert!(ecode.success(), "Failed to execute {}", cmd);
}

pub struct EncryptedTun<T: Sink, U: Stream> {
    sink: T,
    stream: U,
}

impl<T, U> EncryptedTun<T, U>
where T: Sink<SinkItem=Vec<u8>>,
      U: Stream<Item=Vec<u8>>,
      U::Error: std::fmt::Debug,
{
    pub fn new(handle: &Handle) -> Result<
        EncryptedTun<
            SplitSink<Async>,
            SplitStream<Async>
            >>
        {
        
        let tun = Iface::new("vpn%d", Mode::Tun);

        if tun.is_err() {
            eprintln!("ERROR: Permission denied. Try running as superuser");
            ::std::process::exit(1);
        }
       
        let tun_ok = tun.unwrap();
        cmd("ip", &["addr", "add", "dev", tun_ok.name(), "10.107.1.3/24"]);
        cmd("ip", &["link", "set", "up", "dev", tun_ok.name()]);
        let (sink, stream) = Async::new(tun_ok, handle)
            .unwrap()
            .split();
        
        Ok(EncryptedTun {
            sink: sink,
            stream: stream,
        })
    }

    pub fn encrypt(self, key: &Key) -> Result<
        EncryptedTun<
            With<T, Vec<u8>, De, Result<Vec<u8>>>,
            Map<U, En>
            >>
            where std::io::Error: std::convert::From<<T as futures::Sink>::SinkError>
            {
        let encryptor = En::new(&key);
        let decryptor = De::new(&key);
        
        let decrypted_sink = self.sink.with(decryptor);
        let encrypted_stream = self.stream.map(encryptor);
        
        Ok(EncryptedTun {
            sink: decrypted_sink,
            stream: encrypted_stream,
        })
    }

    pub fn split(self) -> (T, U) {
        (self.sink, self.stream)
    }
}

pub struct TcpVecCodec;

impl Decoder for TcpVecCodec {
    type Item = Vec<u8>;
    type Error = std::io::Error;

    fn decode (&mut self, buf: &mut BytesMut) -> std::io::Result<Option<Self::Item>> {
        Ok(Some(buf.iter().cloned().collect()))
    }
}

impl Encoder for TcpVecCodec {
    type Item = Vec<u8>;
    type Error = std::io::Error;

    fn encode (&mut self, item: Self::Item, dst: &mut BytesMut) -> std::io::Result<()> {
        dst.extend_from_slice(item.as_slice());

        Ok(())
    }
}
