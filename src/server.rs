use spake2::{Ed25519Group, Identity, Password, SPAKE2};
use keybob::{Key, KeyType};
use tokio_core::net::TcpStream;
use std::io::{Read, Write};

pub fn handshake(client_num: &u16, server_id: &str, mut sock: &TcpStream, pass: &str) -> Result<Key, String> {
    let (spake, outbound_msg) = SPAKE2::<Ed25519Group>::start_b(
        &Password::new(pass.as_bytes()),
        &Identity::new(format!("client:{}", client_num).as_bytes()),
        &Identity::new(server_id.as_bytes()),
        );

    sock.write(outbound_msg.as_slice()).unwrap();

    let inbound_msg: &mut [u8] = &mut [0u8];
    sock.read(inbound_msg).unwrap();

    let key = spake.finish(&inbound_msg).unwrap();
    let key_pass = format!("{:?}", key);

    Ok(Key::from_pw(KeyType::Aes128, &key_pass, server_id))
}
