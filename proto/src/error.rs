use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WireError {
    #[error("I/O transport error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid protocol magic: expected 0x564E4754, got 0x{0:08X}")]
    InvalidMagic(u32),

    #[error("unsupported protocol version: 0x{0:04X}")]
    UnsupportedVersion(u16),

    #[error("unsupported cipher suite: 0x{0:04X}")]
    UnsupportedCipherSuite(u16),

    #[error("server rejected handshake with status 0x{0:04X}")]
    HandshakeRejected(u16),

    #[error("non-contributory X25519 public key (low-order point rejected)")]
    NonContributoryKey,

    #[error("invalid server Ed25519 identity key or signature verification failed")]
    InvalidServerSignature,

    #[error("invalid Ed25519 key material: {0}")]
    InvalidKeyMaterial(String),

    #[error("frame payload length {0} bytes exceeds limit ({1} bytes)")]
    FrameTooLarge(u32, u32),

    #[error("unknown wire opcode: 0x{0:04X}")]
    UnknownOpcode(u16),

    #[error("ChaCha20-Poly1305 AEAD authentication tag mismatch or corrupted packet")]
    AeadTampered,

    #[error("packet sequence counter exhausted")]
    SequenceOverflow,

    #[error("protobuf decode error: {0}")]
    ProtobufDecode(#[from] prost::DecodeError),

    #[error("protobuf encode error: {0}")]
    ProtobufEncode(#[from] prost::EncodeError),
}

pub type WireResult<T> = Result<T, WireError>;
