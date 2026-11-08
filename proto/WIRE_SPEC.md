# MTWire v1 — Binary Transport & Framing Specification

## 1. Design Principles
- **Zero HTTP/JSON Overhead:** Persistent full-duplex binary stream over TCP (and stream-compatible with QUIC).
- **Little-Endian Wire Order:** All multi-byte integer fields in frame headers use Little-Endian (`uint16_le`, `uint32_le`, `uint64_le`), matching x86_64 and ARM64 native endianness without byte-swapping instructions.
- **1-RTT Forward-Secret AEAD Handshake:** Ephemeral **X25519 (RFC 7748)** key exchange authenticated by server **Ed25519 (RFC 8032)** identity signature, key derivation via **HKDF-SHA256 (RFC 5869)**, and packet encryption via **ChaCha20-Poly1305 IETF (RFC 8439)**.
- **Out-of-Order RPC Multiplexing:** `uint64_le req_id` in the authenticated frame header enables concurrent in-flight requests (`GetHistory`, `SendMessage`, `MediaUploadChunk`, `Ping`) over a single socket without head-of-line RPC blocking.

---

## 2. Cryptographic Handshake (1-RTT)

### 2.1 `ClientHello` (Client -> Server, 44 bytes fixed)
| Offset | Size | Type        | Field             | Description |
|-------:|-----:|-------------|-------------------|-------------|
| `0`    | `4`  | `uint32_le` | `magic`           | `0x564E4754` (`'T','G','N','V'` in memory) |
| `4`    | `2`  | `uint16_le` | `proto_version`   | `0x0001` (MTWire v1) |
| `6`    | `2`  | `uint16_le` | `cipher_suite`    | `0x0001` (`X25519_CHACHA20POLY1305_SHA256`) |
| `8`    | `32` | `bytes[32]` | `client_eph_pub`  | Ephemeral X25519 public key |
| `40`   | `4`  | `bytes[4]`  | `client_nonce`    | CSPRNG random salt contribution |

### 2.2 `ServerHello` (Server -> Client, 108 bytes fixed)
| Offset | Size | Type        | Field             | Description |
|-------:|-----:|-------------|-------------------|-------------|
| `0`    | `4`  | `uint32_le` | `magic`           | `0x564E4754` |
| `4`    | `2`  | `uint16_le` | `proto_version`   | `0x0001` |
| `6`    | `2`  | `uint16_le` | `status`          | `0x0000` = OK, `0x0001` = Unsupported Version |
| `8`    | `32` | `bytes[32]` | `server_eph_pub`  | Ephemeral X25519 public key |
| `40`   | `4`  | `bytes[4]`  | `server_nonce`    | CSPRNG random salt contribution |
| `44`   | `64` | `bytes[64]` | `ed25519_sig`     | Ed25519 signature over `transcript` (`80 bytes`) |

Where `transcript` (`80 bytes`) signed by the server's pinned static Ed25519 private key is:
```text
transcript = magic(4) || proto_version(2) || cipher_suite(2)
          || client_eph_pub(32) || client_nonce(4)
          || server_eph_pub(32) || server_nonce(4)
```

### 2.3 Directional Session Key Schedule (`HKDF-SHA256`)
1. `shared_secret = X25519(my_eph_priv, peer_eph_pub)` (`32 bytes`; reject all-zero output per RFC 7748).
2. `salt = client_nonce(4) || server_nonce(4) || client_eph_pub(32) || server_eph_pub(32)` (`72 bytes`).
3. `prk = HKDF-Extract(SHA256, salt, shared_secret)` (`32 bytes`).
4. `okm = HKDF-Expand(SHA256, prk, info = "MTWire-v1-AEAD-Keys", L = 72)`:
   - `c2s_key       = okm[0..32]`   (Client-to-Server 256-bit ChaCha20-Poly1305 key)
   - `s2c_key       = okm[32..64]`  (Server-to-Client 256-bit ChaCha20-Poly1305 key)
   - `c2s_iv_prefix = okm[64..68]`  (Client-to-Server 32-bit nonce prefix)
   - `s2c_iv_prefix = okm[68..72]`  (Server-to-Client 32-bit nonce prefix)
5. Zeroize `my_eph_priv`, `shared_secret`, `prk`, and `okm` immediately after session setup.

---

## 3. Encrypted Frame Layout

Every post-handshake message is transmitted as a discrete AEAD frame (`32 bytes` total framing + MAC overhead):

```text
+-------------------------------------------------------------------+
| 0..3    payload_len  (uint32_le) : N bytes (0 <= N <= 4,194,304)  | \
| 4..5    opcode       (uint16_le) : Packet Opcode (0x0001..0x0055) |  | 16-byte Header
| 6..7    flags        (uint16_le) : Bitflags (0x0000 default)      |  | (Cleartext AAD)
| 8..15   req_id       (uint64_le) : Client correlation ID / 0 push | /
+-------------------------------------------------------------------+
| 16..16+N-1           ciphertext  : ChaCha20-encrypted Protobuf    | \  N + 16 bytes
| 16+N..31+N           poly1305_tag: 128-bit authentication MAC     | /  AEAD Seal
+-------------------------------------------------------------------+
```

### 3.1 Nonce Construction & Anti-Replay
- Both peers maintain two independent 64-bit unsigned sequence counters initialized to `0` after handshake: `c2s_seq` and `s2c_seq`.
- For frame `seq`, the 96-bit (12-byte) RFC 8439 nonce is:
  ```text
  nonce[0..4]  = iv_prefix[0..4]
  nonce[4..12] = uint64_le(seq)
  ```
- `header[0..16]` is supplied as `AAD` (Additional Authenticated Data) to `ChaCha20-Poly1305`.
- `seq` increments by `1` after every sealed/opened frame. Any Poly1305 tag verification failure or `payload_len > 4 MiB` immediately terminates the TCP connection.

### 3.2 Header `flags` Bitmask (`uint16_le`)
- `0x0001` (`FLAG_SERVER_PUSH`): Frame initiated asynchronously by server (`req_id == 0`).
- `0x0002` (`FLAG_NEEDS_ACK`): Receiver should prioritize immediate delivery acknowledgment.
- `0x0004` (`FLAG_COMPRESSED_LZ4`): Reserved for optional LZ4 payload compression on large history batches.

---

## 4. Keep-Alive & Reconnection Semantics
- Client `NetworkThread` sends `OP_PING (0x0001)` every **25 seconds** of socket inactivity.
- If `OP_PONG (0x0002)` is not received within **10 seconds**, client aborts socket and enters exponential backoff (`250ms`, `500ms`, `1000ms`, `2000ms`, capped at `5000ms` ± 20% random jitter).
- Upon reconnect, client performs fresh X25519 handshake -> sends `OP_AUTH_REQ` with `AUTH_METHOD_TOKEN_RESUME` + `last_known_pts` -> flushes any pending unacknowledged `OP_SEND_MESSAGE_REQ` queued in SQLite outbox (deduplicated server-side by `(sender_id, client_random_id)`).
