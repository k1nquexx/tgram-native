use bytes::{Buf, Bytes, BytesMut};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use prost::Message;
use zeroize::Zeroize;

use crate::error::{WireError, WireResult};
use crate::opcodes::{
    Opcode, AEAD_TAG_LEN, FRAME_HEADER_LEN, MAX_FRAME_PAYLOAD_LEN,
};

/// Cleartext 16-byte frame header authenticated as AEAD Associated Data (AAD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub payload_len: u32,
    pub opcode: Opcode,
    pub flags: u16,
    pub req_id: u64,
}

impl FrameHeader {
    #[inline]
    pub fn encode(&self) -> [u8; FRAME_HEADER_LEN] {
        let mut out = [0u8; FRAME_HEADER_LEN];
        out[0..4].copy_from_slice(&self.payload_len.to_le_bytes());
        out[4..6].copy_from_slice(&self.opcode.as_u16().to_le_bytes());
        out[6..8].copy_from_slice(&self.flags.to_le_bytes());
        out[8..16].copy_from_slice(&self.req_id.to_le_bytes());
        out
    }

    #[inline]
    pub fn decode(raw: &[u8; FRAME_HEADER_LEN]) -> WireResult<Self> {
        let payload_len = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        if payload_len > MAX_FRAME_PAYLOAD_LEN {
            return Err(WireError::FrameTooLarge(payload_len, MAX_FRAME_PAYLOAD_LEN));
        }
        let opcode_raw = u16::from_le_bytes([raw[4], raw[5]]);
        let opcode = Opcode::try_from(opcode_raw)?;
        let flags = u16::from_le_bytes([raw[6], raw[7]]);
        let req_id = u64::from_le_bytes([
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        ]);
        Ok(Self {
            payload_len,
            opcode,
            flags,
            req_id,
        })
    }
}

/// Decrypted frame yielded by [`FrameOpener`].
#[derive(Debug, Clone)]
pub struct DecodedFrame {
    pub header: FrameHeader,
    pub payload: Bytes,
}

impl DecodedFrame {
    #[inline]
    pub fn decode_proto<M: Message + Default>(&self) -> WireResult<M> {
        Ok(M::decode(self.payload.clone())?)
    }
}

#[inline]
fn compute_nonce_and_next_seq(iv_prefix: &[u8; 4], seq: u64) -> WireResult<([u8; 12], u64)> {
    let next_seq = seq.checked_add(1).ok_or(WireError::SequenceOverflow)?;
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(iv_prefix);
    nonce[4..12].copy_from_slice(&seq.to_le_bytes());
    Ok((nonce, next_seq))
}

/// Write-half AEAD sealer (owned exclusively by socket writer task — zero mutexes).
pub struct FrameSealer {
    cipher: ChaCha20Poly1305,
    iv_prefix: [u8; 4],
    seq: u64,
}

impl Drop for FrameSealer {
    fn drop(&mut self) {
        self.iv_prefix.zeroize();
        self.seq.zeroize();
    }
}

impl FrameSealer {
    pub fn new(mut key_bytes: [u8; 32], iv_prefix: [u8; 4]) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        key_bytes.zeroize();
        Self {
            cipher,
            iv_prefix,
            seq: 0,
        }
    }

    /// Encodes a Protobuf message directly into `dst` and encrypts it in-place (zero intermediate heap allocs).
    /// Guarantees atomic sequence and buffer state: `self.seq` is incremented ONLY after encoding and AEAD succeed.
    pub fn seal_proto<M: Message>(
        &mut self,
        opcode: Opcode,
        flags: u16,
        req_id: u64,
        msg: &M,
        dst: &mut BytesMut,
    ) -> WireResult<()> {
        let payload_len = msg.encoded_len();
        if payload_len > MAX_FRAME_PAYLOAD_LEN as usize {
            return Err(WireError::FrameTooLarge(
                payload_len as u32,
                MAX_FRAME_PAYLOAD_LEN,
            ));
        }

        let (mut nonce, next_seq) = compute_nonce_and_next_seq(&self.iv_prefix, self.seq)?;

        let header = FrameHeader {
            payload_len: payload_len as u32,
            opcode,
            flags,
            req_id,
        };
        let aad = header.encode();

        let start = dst.len();
        dst.reserve(FRAME_HEADER_LEN + payload_len + AEAD_TAG_LEN);
        dst.extend_from_slice(&aad);
        if let Err(err) = msg.encode(dst) {
            dst.truncate(start);
            nonce.zeroize();
            return Err(err.into());
        }

        let actual_payload_len = dst.len() - (start + FRAME_HEADER_LEN);
        if actual_payload_len != payload_len {
            dst.truncate(start);
            nonce.zeroize();
            return Err(WireError::AeadTampered);
        }

        let payload_slice =
            &mut dst[start + FRAME_HEADER_LEN..start + FRAME_HEADER_LEN + payload_len];
        let tag = match self.cipher.encrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            &aad,
            payload_slice,
        ) {
            Ok(t) => t,
            Err(_) => {
                dst.truncate(start);
                nonce.zeroize();
                return Err(WireError::AeadTampered);
            }
        };

        nonce.zeroize();
        dst.extend_from_slice(tag.as_slice());
        self.seq = next_seq;
        Ok(())
    }

    /// Seals pre-encoded Protobuf payload bytes into `dst` (useful for fanout of pre-serialized updates).
    /// Guarantees atomic sequence and buffer state: `self.seq` is incremented ONLY after AEAD succeeds.
    pub fn seal_raw(
        &mut self,
        opcode: Opcode,
        flags: u16,
        req_id: u64,
        plaintext: &[u8],
        dst: &mut BytesMut,
    ) -> WireResult<()> {
        if plaintext.len() > MAX_FRAME_PAYLOAD_LEN as usize {
            return Err(WireError::FrameTooLarge(
                plaintext.len() as u32,
                MAX_FRAME_PAYLOAD_LEN,
            ));
        }

        let (mut nonce, next_seq) = compute_nonce_and_next_seq(&self.iv_prefix, self.seq)?;

        let header = FrameHeader {
            payload_len: plaintext.len() as u32,
            opcode,
            flags,
            req_id,
        };
        let aad = header.encode();

        let start = dst.len();
        dst.reserve(FRAME_HEADER_LEN + plaintext.len() + AEAD_TAG_LEN);
        dst.extend_from_slice(&aad);
        dst.extend_from_slice(plaintext);

        let payload_slice =
            &mut dst[start + FRAME_HEADER_LEN..start + FRAME_HEADER_LEN + plaintext.len()];
        let tag = match self.cipher.encrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            &aad,
            payload_slice,
        ) {
            Ok(t) => t,
            Err(_) => {
                dst.truncate(start);
                nonce.zeroize();
                return Err(WireError::AeadTampered);
            }
        };

        nonce.zeroize();
        dst.extend_from_slice(tag.as_slice());
        self.seq = next_seq;
        Ok(())
    }

    #[inline]
    pub fn sequence(&self) -> u64 {
        self.seq
    }

    #[cfg(test)]
    pub(crate) fn set_sequence_for_test(&mut self, seq: u64) {
        self.seq = seq;
    }
}

/// Read-half AEAD opener (owned exclusively by socket reader task — zero mutexes).
pub struct FrameOpener {
    cipher: ChaCha20Poly1305,
    iv_prefix: [u8; 4],
    seq: u64,
}

impl Drop for FrameOpener {
    fn drop(&mut self) {
        self.iv_prefix.zeroize();
        self.seq.zeroize();
    }
}

impl FrameOpener {
    pub fn new(mut key_bytes: [u8; 32], iv_prefix: [u8; 4]) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        key_bytes.zeroize();
        Self {
            cipher,
            iv_prefix,
            seq: 0,
        }
    }

    /// Attempts to extract and authenticate one complete frame from `rx_buf`.
    /// Returns `Ok(None)` if more bytes must be read from the socket.
    pub fn try_open_next(&mut self, rx_buf: &mut BytesMut) -> WireResult<Option<DecodedFrame>> {
        if rx_buf.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }

        let mut aad = [0u8; FRAME_HEADER_LEN];
        aad.copy_from_slice(&rx_buf[..FRAME_HEADER_LEN]);
        let header = FrameHeader::decode(&aad)?;

        let payload_len = header.payload_len as usize;
        let total_len = FRAME_HEADER_LEN + payload_len + AEAD_TAG_LEN;
        if rx_buf.len() < total_len {
            rx_buf.reserve(total_len - rx_buf.len());
            return Ok(None);
        }

        let (mut nonce, next_seq) = compute_nonce_and_next_seq(&self.iv_prefix, self.seq)?;

        let mut frame_buf = rx_buf.split_to(total_len);
        frame_buf.advance(FRAME_HEADER_LEN);
        let tag_buf = frame_buf.split_off(payload_len);

        let decrypt_res = self.cipher.decrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            &aad,
            &mut frame_buf[..],
            Tag::from_slice(&tag_buf),
        );
        nonce.zeroize();
        decrypt_res.map_err(|_| WireError::AeadTampered)?;

        self.seq = next_seq;
        Ok(Some(DecodedFrame {
            header,
            payload: frame_buf.freeze(),
        }))
    }

    #[inline]
    pub fn sequence(&self) -> u64 {
        self.seq
    }

    #[cfg(test)]
    pub(crate) fn set_sequence_for_test(&mut self, seq: u64) {
        self.seq = seq;
    }
}
