use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

use crate::error::{WireError, WireResult};
use crate::frame::{FrameOpener, FrameSealer};
use crate::opcodes::{
    CIPHER_SUITE_X25519_CHACHA20POLY1305, CLIENT_HELLO_LEN, PROTO_VERSION_V1,
    SERVER_HELLO_LEN, WIRE_MAGIC,
};

const HKDF_INFO: &[u8] = b"MTWire-v1-AEAD-Keys";

/// Deterministic default Ed25519 seed for zero-config local/LAN deployment.
/// Override in production via `TGRAM_SERVER_KEY_HEX` and `TGRAM_SERVER_PUBKEY_HEX`.
pub const DEFAULT_SERVER_IDENTITY_SEED: [u8; 32] = [
    0x54, 0x47, 0x52, 0x41, 0x4D, 0x2D, 0x4E, 0x41,
    0x54, 0x49, 0x56, 0x45, 0x2D, 0x4D, 0x54, 0x57,
    0x49, 0x52, 0x45, 0x2D, 0x56, 0x31, 0x2D, 0x4B,
    0x45, 0x59, 0x2D, 0x32, 0x30, 0x32, 0x36, 0x21,
];

pub fn default_server_signing_key() -> SigningKey {
    SigningKey::from_bytes(&DEFAULT_SERVER_IDENTITY_SEED)
}

pub fn default_server_verifying_key() -> VerifyingKey {
    default_server_signing_key().verifying_key()
}

/// 44-byte `ClientHello` wire packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientHello {
    pub proto_version: u16,
    pub cipher_suite: u16,
    pub client_eph_pub: [u8; 32],
    pub client_nonce: [u8; 4],
}

impl ClientHello {
    pub fn encode(&self) -> [u8; CLIENT_HELLO_LEN] {
        let mut buf = [0u8; CLIENT_HELLO_LEN];
        buf[0..4].copy_from_slice(&WIRE_MAGIC.to_le_bytes());
        buf[4..6].copy_from_slice(&self.proto_version.to_le_bytes());
        buf[6..8].copy_from_slice(&self.cipher_suite.to_le_bytes());
        buf[8..40].copy_from_slice(&self.client_eph_pub);
        buf[40..44].copy_from_slice(&self.client_nonce);
        buf
    }

    pub fn decode(buf: &[u8; CLIENT_HELLO_LEN]) -> WireResult<Self> {
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != WIRE_MAGIC {
            return Err(WireError::InvalidMagic(magic));
        }
        let proto_version = u16::from_le_bytes([buf[4], buf[5]]);
        if proto_version != PROTO_VERSION_V1 {
            return Err(WireError::UnsupportedVersion(proto_version));
        }
        let cipher_suite = u16::from_le_bytes([buf[6], buf[7]]);
        if cipher_suite != CIPHER_SUITE_X25519_CHACHA20POLY1305 {
            return Err(WireError::UnsupportedCipherSuite(cipher_suite));
        }

        let mut client_eph_pub = [0u8; 32];
        client_eph_pub.copy_from_slice(&buf[8..40]);
        let mut client_nonce = [0u8; 4];
        client_nonce.copy_from_slice(&buf[40..44]);

        Ok(Self {
            proto_version,
            cipher_suite,
            client_eph_pub,
            client_nonce,
        })
    }
}

/// 108-byte `ServerHello` wire packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHello {
    pub proto_version: u16,
    pub status: u16,
    pub server_eph_pub: [u8; 32],
    pub server_nonce: [u8; 4],
    pub ed25519_sig: [u8; 64],
}

impl ServerHello {
    pub fn encode(&self) -> [u8; SERVER_HELLO_LEN] {
        let mut buf = [0u8; SERVER_HELLO_LEN];
        buf[0..4].copy_from_slice(&WIRE_MAGIC.to_le_bytes());
        buf[4..6].copy_from_slice(&self.proto_version.to_le_bytes());
        buf[6..8].copy_from_slice(&self.status.to_le_bytes());
        buf[8..40].copy_from_slice(&self.server_eph_pub);
        buf[40..44].copy_from_slice(&self.server_nonce);
        buf[44..108].copy_from_slice(&self.ed25519_sig);
        buf
    }

    pub fn decode(buf: &[u8; SERVER_HELLO_LEN]) -> WireResult<Self> {
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != WIRE_MAGIC {
            return Err(WireError::InvalidMagic(magic));
        }
        let proto_version = u16::from_le_bytes([buf[4], buf[5]]);
        if proto_version != PROTO_VERSION_V1 {
            return Err(WireError::UnsupportedVersion(proto_version));
        }
        let status = u16::from_le_bytes([buf[6], buf[7]]);
        if status != 0 {
            return Err(WireError::HandshakeRejected(status));
        }

        let mut server_eph_pub = [0u8; 32];
        server_eph_pub.copy_from_slice(&buf[8..40]);
        let mut server_nonce = [0u8; 4];
        server_nonce.copy_from_slice(&buf[40..44]);
        let mut ed25519_sig = [0u8; 64];
        ed25519_sig.copy_from_slice(&buf[44..108]);

        Ok(Self {
            proto_version,
            status,
            server_eph_pub,
            server_nonce,
            ed25519_sig,
        })
    }
}

/// Builds the 80-byte signed handshake transcript preventing MITM downgrade or key substitution.
fn build_transcript(
    client_hello: &ClientHello,
    server_eph_pub: &[u8; 32],
    server_nonce: &[u8; 4],
) -> [u8; 80] {
    let mut transcript = [0u8; 80];
    transcript[0..4].copy_from_slice(&WIRE_MAGIC.to_le_bytes());
    transcript[4..6].copy_from_slice(&client_hello.proto_version.to_le_bytes());
    transcript[6..8].copy_from_slice(&client_hello.cipher_suite.to_le_bytes());
    transcript[8..40].copy_from_slice(&client_hello.client_eph_pub);
    transcript[40..44].copy_from_slice(&client_hello.client_nonce);
    transcript[44..76].copy_from_slice(server_eph_pub);
    transcript[76..80].copy_from_slice(server_nonce);
    transcript
}

/// Derives directional `ChaCha20-Poly1305` AEAD session halves via `HKDF-SHA256` and zeroizes key material.
fn derive_session_halves(
    shared_secret_bytes: &[u8; 32],
    client_hello: &ClientHello,
    server_eph_pub: &[u8; 32],
    server_nonce: &[u8; 4],
    is_client: bool,
) -> (FrameSealer, FrameOpener) {
    let mut salt = [0u8; 72];
    salt[0..4].copy_from_slice(&client_hello.client_nonce);
    salt[4..8].copy_from_slice(server_nonce);
    salt[8..40].copy_from_slice(&client_hello.client_eph_pub);
    salt[40..72].copy_from_slice(server_eph_pub);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret_bytes);
    let mut okm = [0u8; 72];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("72-byte HKDF-SHA256 output length is valid");

    let mut c2s_key = [0u8; 32];
    c2s_key.copy_from_slice(&okm[0..32]);
    let mut s2c_key = [0u8; 32];
    s2c_key.copy_from_slice(&okm[32..64]);

    let mut c2s_iv = [0u8; 4];
    c2s_iv.copy_from_slice(&okm[64..68]);
    let mut s2c_iv = [0u8; 4];
    s2c_iv.copy_from_slice(&okm[68..72]);

    okm.zeroize();
    salt.zeroize();

    let pair = if is_client {
        (
            FrameSealer::new(c2s_key, c2s_iv),
            FrameOpener::new(s2c_key, s2c_iv),
        )
    } else {
        (
            FrameSealer::new(s2c_key, s2c_iv),
            FrameOpener::new(c2s_key, c2s_iv),
        )
    };

    c2s_key.zeroize();
    s2c_key.zeroize();
    c2s_iv.zeroize();
    s2c_iv.zeroize();

    pair
}

/// Executes 1-RTT client-side handshake over any async byte stream (TCP / QUIC).
pub async fn perform_client_handshake<S>(
    stream: &mut S,
    pinned_server_key: &VerifyingKey,
) -> WireResult<(FrameSealer, FrameOpener)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let client_eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_eph_pub = PublicKey::from(&client_eph_secret).to_bytes();
    let mut client_nonce = [0u8; 4];
    OsRng.fill_bytes(&mut client_nonce);

    let client_hello = ClientHello {
        proto_version: PROTO_VERSION_V1,
        cipher_suite: CIPHER_SUITE_X25519_CHACHA20POLY1305,
        client_eph_pub,
        client_nonce,
    };

    let ch_bytes = client_hello.encode();
    stream.write_all(&ch_bytes).await?;
    stream.flush().await?;

    let mut sh_bytes = [0u8; SERVER_HELLO_LEN];
    stream.read_exact(&mut sh_bytes).await?;
    let server_hello = ServerHello::decode(&sh_bytes)?;

    let transcript = build_transcript(
        &client_hello,
        &server_hello.server_eph_pub,
        &server_hello.server_nonce,
    );
    let signature = Signature::from_bytes(&server_hello.ed25519_sig);
    pinned_server_key
        .verify(&transcript, &signature)
        .map_err(|_| WireError::InvalidServerSignature)?;

    let peer_pub = PublicKey::from(server_hello.server_eph_pub);
    let shared = client_eph_secret.diffie_hellman(&peer_pub);
    if !shared.was_contributory() {
        return Err(WireError::NonContributoryKey);
    }

    Ok(derive_session_halves(
        shared.as_bytes(),
        &client_hello,
        &server_hello.server_eph_pub,
        &server_hello.server_nonce,
        true,
    ))
}

/// Executes 1-RTT server-side handshake over any async byte stream (TCP / QUIC).
pub async fn perform_server_handshake<S>(
    stream: &mut S,
    server_identity: &SigningKey,
) -> WireResult<(FrameSealer, FrameOpener)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut ch_bytes = [0u8; CLIENT_HELLO_LEN];
    stream.read_exact(&mut ch_bytes).await?;
    let client_hello = ClientHello::decode(&ch_bytes)?;

    let server_eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_eph_pub = PublicKey::from(&server_eph_secret).to_bytes();
    let mut server_nonce = [0u8; 4];
    OsRng.fill_bytes(&mut server_nonce);

    let peer_pub = PublicKey::from(client_hello.client_eph_pub);
    let shared = server_eph_secret.diffie_hellman(&peer_pub);
    if !shared.was_contributory() {
        return Err(WireError::NonContributoryKey);
    }

    let transcript = build_transcript(&client_hello, &server_eph_pub, &server_nonce);
    let sig: Signature = server_identity.sign(&transcript);

    let server_hello = ServerHello {
        proto_version: PROTO_VERSION_V1,
        status: 0,
        server_eph_pub,
        server_nonce,
        ed25519_sig: sig.to_bytes(),
    };

    let sh_bytes = server_hello.encode();
    stream.write_all(&sh_bytes).await?;
    stream.flush().await?;

    Ok(derive_session_halves(
        shared.as_bytes(),
        &client_hello,
        &server_eph_pub,
        &server_nonce,
        false,
    ))
}
