use spake2::{Ed25519Group, Identity, Password, SPAKE2};
use keybob::{Key, KeyType};
use tokio_core::net::UdpSocket;
use futures::prelude::*;
use futures_retry::{FutureRetry, RetryPolicy};
use std::net::SocketAddr;
use std::time::Duration;
use std::io::Error;

pub fn handshake(client_num: &i32, server_id: &str, sock: &UdpSocket, pass: &str) -> Result<(Key, SocketAddr), String> {
    let (spake, outbound_msg) = SPAKE2::<Ed25519Group>::start_b(
        &Password::new(pass.as_bytes()),
        &Identity::new(format!("client:{}", client_num).as_bytes()),
        &Identity::new(server_id.as_bytes()),
        );

    let inbound_msg: &mut [u8] = &mut [0u8];
    let (_num, client_addr) = FutureRetry::new(|| sock.recv_from(inbound_msg).into_future(), |_| {
        eprintln!("ERROR: Failed handshake (receiving password from client). Trying again...");
        RetryPolicy::<Error>::WaitRetry(Duration::new(5, 0))
    })
        .wait()
        .unwrap();
    FutureRetry::new(|| sock.connect(&client_addr).into_future(), |_| {
        eprintln!("ERROR: Unable to connect to client. Trying again...");
        RetryPolicy::<Error>::WaitRetry(Duration::new(5, 0))
    })
        .wait()
        .unwrap();
    FutureRetry::new(|| sock.send(outbound_msg.as_slice()).into_future(), |_| {
        eprintln!("ERROR: Unable to connect to client. Trying again...");
        RetryPolicy::<Error>::WaitRetry(Duration::new(5, 0))
    })
        .wait()
        .unwrap();

    let key = spake.finish(&inbound_msg).unwrap();
    let key_pass = format!("{:?}", key);
    
    Ok((Key::from_pw(KeyType::Aes128, &key_pass, server_id), client_addr))
}
