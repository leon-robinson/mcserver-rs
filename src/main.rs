use std::{net::TcpListener, time::Duration};

use once_cell::sync::Lazy;
use protocol::{
    BadI32ToUsizeConversionSnafu, BadUsizeToI32ConversionSnafu, ClientboundPacket,
    EncryptionRequest, PrivateKeyGenerationFailedSnafu, PublicKeyDocumentConversionFailedSnafu,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use rsa::{pkcs8::EncodePublicKey, RsaPrivateKey, RsaPublicKey};
use snafu::ResultExt;

// Configuration, will put in a file config soon.
pub const BIND_IP: &str = "127.0.0.1";
pub const PORT: &str = "25565";
pub const STREAM_READ_TIMEOUT: Duration = Duration::from_secs(5);
pub const STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

// Not yet used constants.
pub const _CONNECTION_STREAM_THREAD_POOL_SIZE: i32 = 4;

pub mod byte_helpers;
pub mod connection_handler;
pub mod log;
pub mod macros;
pub mod protocol;

pub static KEY_AND_REQUEST: Lazy<(RsaPrivateKey, Vec<u8>)> = Lazy::new(|| {
    let mut rng = StdRng::from_entropy();
    let public_key_bits: i32 = 1024;

    let private_key = RsaPrivateKey::new(
        &mut rng,
        usize::try_from(public_key_bits)
            .context(BadI32ToUsizeConversionSnafu)
            .unwrap(),
    )
    .context(PrivateKeyGenerationFailedSnafu)
    .unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    let public_key_bytes = RsaPublicKey::to_public_key_der(&public_key)
        .context(PublicKeyDocumentConversionFailedSnafu)
        .unwrap()
        .to_vec();

    let encryption_request = EncryptionRequest::to_bytes(EncryptionRequest {
        server_id: String::new(),
        public_key_len: public_key_bytes
            .len()
            .try_into()
            .context(BadUsizeToI32ConversionSnafu)
            .unwrap(),
        public_key: public_key_bytes,
        verify_token_length: 4,
        verify_token: rng.gen(),
    })
    .unwrap();

    (private_key, encryption_request)
});

fn main() {
    let tcp_listener =
        TcpListener::bind(format!("{BIND_IP}:{PORT}")).expect("Failed to bind TcpListener.");

    // TODO: Use a thread pool.
    for stream in tcp_listener.incoming() {
        println!("[NEW CONNECTION]");
        connection_handler::handle_connection(stream.unwrap());
    }
}
