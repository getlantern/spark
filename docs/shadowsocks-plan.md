# Shadowsocks 2022 Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Shadowsocks 2022 (SIP022) as a spark client `Transport` (TCP, three `2022-blake3-*` ciphers) and `UdpTransport` (UDP, the two AES methods), wire-interoperable with deployed `shadowsocks-rust` servers.

**Architecture:** A from-scratch SS-2022 implementation under `core/src/transport/shadowsocks/`, behind a `shadowsocks` cargo feature. `ring` provides the AEADs (12-byte-nonce AES-GCM / ChaCha20-Poly1305 via `LessSafeKey`); RustCrypto `blake3` derives session subkeys and `aes` provides the raw block cipher for the UDP separate-header. TCP is one SS connection per `dial()` (SS-2022 maps TCP 1:1) presented as an `AsyncRead+AsyncWrite` `BoxedStream`; UDP returns split `PacketSink`/`PacketSource` halves carrying the native session-ID/packet-ID packet format with a WireGuard-style sliding-window replay filter.

**Tech Stack:** Rust, tokio, `ring` (AEAD), `blake3` + `aes` (RustCrypto, feature-gated), `bytes`, `async-trait`. Spec: `docs/shadowsocks-design.md` (SIP022 = `Shadowsocks-NET/shadowsocks-specs/2022-1-shadowsocks-2022-edition.md`).

**Conventions (spark CLAUDE.md — apply to every task):** one `thiserror` `Error` enum per module; no `unwrap()`/`expect()` outside tests/startup; `BytesMut` (not `Vec<u8>`) on data paths, allocated `with_capacity`; no `MutexGuard` held across `.await`; only cancel-safe futures inside `select!`/`poll`; `cargo fmt` + `cargo clippy --all-targets -- -D warnings` clean before every commit. **Verification discipline:** the exact `blake3::derive_key`, `aes` block-trait, and `ring::aead` signatures must be checked against docs.rs before use — do not guess. The in-repo `ring::aead` idiom to mirror is `core/src/transport/wasm/mod.rs:710-750` (`LessSafeKey::new(UnboundKey::new(&ALG, &key)?)` → `seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(&[]), &mut buf)` / `open_in_place(...)`).

**The authoritative oracle is interop (Task 14), not this prose.** Where a byte layout here disagrees with what a live `shadowsocks-rust` server accepts, the server is right — fix the code and the KAT vectors, not the test expectation.

---

## File Structure

| File | Responsibility |
|---|---|
| `core/src/config/mod.rs` (modify) | `SsMethod` enum (serde + size helpers), `ShadowsocksConfig`, `ServerSpec::Shadowsocks`, `TransportConfig.shadowsocks`, `first_unresolved_host` arm |
| `core/src/bootstrap/mod.rs` (modify) | `resolve_endpoints` arm (optional-SNI refactor — SS has no SNI) |
| `core/src/transport/mod.rs` (modify) | `shadowsocks_transport` builder, `from_config` precedence, `build_one` arm, `pub mod shadowsocks` gate |
| `core/src/transport/shadowsocks/mod.rs` (create) | `ShadowsocksTransport` (impl `Transport` + `UdpTransport`), SOCKS-address codec, `Error` enum, version/label consts |
| `core/src/transport/shadowsocks/crypto.rs` (create) | base64 PSK decode, `blake3` subkey, `NonceCounter`, ring AEAD `Cipher`, raw-AES block |
| `core/src/transport/shadowsocks/tcp.rs` (create) | TCP request/response codec + `ShadowsocksStream` (`AsyncRead+AsyncWrite`) |
| `core/src/transport/shadowsocks/udp.rs` (create) | UDP packet build/parse, sliding-window filter, `ShadowsocksUdpSink`/`Source` |
| `core/Cargo.toml` (modify) | `shadowsocks` feature; optional `blake3`, `aes` deps |
| `Cargo.toml` (modify) | `[workspace.dependencies]` `blake3`, `aes` |
| `docs/adr/0009-shadowsocks-transport.md` (create) | the ADR |

---

## Task 1: Config types (`SsMethod`, `ShadowsocksConfig`, `TransportConfig.shadowsocks`)

These live in `core/src/config/mod.rs` (always compiled, like `AnytlsConfig` — config exists even without the transport feature). `SsMethod`'s size helpers are plain (ring-agnostic), so they live here too.

**Files:**
- Modify: `core/src/config/mod.rs`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `core/src/config/mod.rs`:

```rust
#[test]
fn shadowsocks_method_sizes() {
    assert_eq!(SsMethod::Aes128Gcm.key_len(), 16);
    assert_eq!(SsMethod::Aes128Gcm.salt_len(), 16);
    assert_eq!(SsMethod::Aes256Gcm.key_len(), 32);
    assert!(SsMethod::Aes256Gcm.is_aes());
    assert_eq!(SsMethod::Chacha20Poly1305.key_len(), 32);
    assert!(!SsMethod::Chacha20Poly1305.is_aes());
}

#[test]
fn shadowsocks_config_round_trips_through_toml() {
    let toml = r#"
[transport.shadowsocks]
server = "1.2.3.4:8388"
method = "2022-blake3-aes-256-gcm"
password = "c29tZS1iYXNlNjQtcHNr"
"#;
    let cfg = Config::from_toml_str(toml).unwrap();
    let ss = cfg.transport.shadowsocks.unwrap();
    assert_eq!(ss.method, SsMethod::Aes256Gcm);
    assert_eq!(ss.password, "c29tZS1iYXNlNjQtcHNr");
    // Round-trips back out.
    let out = cfg.to_toml_string().unwrap();
    assert!(out.contains("2022-blake3-aes-256-gcm"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p spark-core config::tests::shadowsocks`
Expected: FAIL — `SsMethod` / `transport.shadowsocks` not defined (compile error).

(If the crate name is not `spark-core`, use the name from `core/Cargo.toml`'s `[package].name`.)

- [ ] **Step 3: Add the types**

In `core/src/config/mod.rs`, next to `SamizdatConfig`/`TunnelConfig`, add:

```rust
/// The Shadowsocks 2022 (SIP022) methods spark implements. The `rename` values are the canonical
/// method names used by shadowsocks-rust / sing-box config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum SsMethod {
    /// `2022-blake3-aes-128-gcm` — 16-byte key/salt. TCP + UDP.
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Aes128Gcm,
    /// `2022-blake3-aes-256-gcm` — 32-byte key/salt. TCP + UDP.
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Aes256Gcm,
    /// `2022-blake3-chacha20-poly1305` — 32-byte key/salt. TCP only in v1 (UDP needs XChaCha20).
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Chacha20Poly1305,
}

impl SsMethod {
    /// PSK / session-subkey length in bytes (SIP022 §2.1).
    pub fn key_len(self) -> usize {
        match self {
            SsMethod::Aes128Gcm => 16,
            SsMethod::Aes256Gcm | SsMethod::Chacha20Poly1305 => 32,
        }
    }
    /// Per-stream random salt length — equal to the key length (SIP022 §2.2).
    pub fn salt_len(self) -> usize {
        self.key_len()
    }
    /// Whether this is an AES-GCM method (the UDP-capable family in v1).
    pub fn is_aes(self) -> bool {
        matches!(self, SsMethod::Aes128Gcm | SsMethod::Aes256Gcm)
    }
}

/// Shadowsocks 2022 (SIP022) transport configuration (ADR 0009). A pre-shared-key AEAD tunnel,
/// wire-interoperable with deployed shadowsocks-rust / sing-box SS-2022 servers. See
/// `docs/shadowsocks-design.md`. Requires the `shadowsocks` build feature (else `from_config` errors).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowsocksConfig {
    /// The SS server address — `IP:port` or `host:port` (resolved at startup).
    pub server: Endpoint,
    /// The SS-2022 method (cipher); sets key/salt size and the AEAD construction.
    pub method: SsMethod,
    /// The pre-shared key, base64-encoded. Decoded length MUST equal `method.key_len()`.
    pub password: String,
}
```

Add the `ServerSpec` variant:

```rust
    /// Shadowsocks 2022 (ADR 0009).
    Shadowsocks(ShadowsocksConfig),
```

Add the field to `TransportConfig` (after `samizdat`):

```rust
    /// Shadowsocks 2022 transport (ADR 0009): when set, flows tunnel through this SS-2022 server.
    /// Takes precedence over the plain `server` tunnel. Requires the `shadowsocks` build feature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shadowsocks: Option<ShadowsocksConfig>,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p spark-core config::tests::shadowsocks`
Expected: PASS.

- [ ] **Step 5: Fix any struct-literal sites broken by the new field**

Adding a field to `TransportConfig` breaks any literal that does not use `..Default::default()`.

Run: `cargo build -p spark-core --all-targets 2>&1 | grep -A2 "missing field" || echo "no literal breaks"`
For each break (likely in `core/src/transport/mod.rs`, `core/src/bootstrap/mod.rs` test modules, and especially `cli/src/main.rs`), add `..Default::default()` to the `TransportConfig { ... }` literal (or set `shadowsocks: None`). Then:

Run: `cargo build --all-targets`
Expected: clean build (no missing-field errors anywhere in the workspace).

- [ ] **Step 6: Commit**

```bash
git add core/src/config/mod.rs core/src/transport/mod.rs core/src/bootstrap/mod.rs cli/src/main.rs
git commit -m "feat(shadowsocks): config types (SsMethod, ShadowsocksConfig)"
```

---

## Task 2: `shadowsocks` cargo feature + module skeleton

**Files:**
- Modify: `Cargo.toml` (workspace deps), `core/Cargo.toml` (feature + optional deps)
- Modify: `core/src/transport/mod.rs` (gated `pub mod shadowsocks;`)
- Create: `core/src/transport/shadowsocks/mod.rs`, `crypto.rs`, `tcp.rs`, `udp.rs`

- [ ] **Step 1: Add workspace deps**

In the root `Cargo.toml` `[workspace.dependencies]`:

```toml
blake3 = { version = "1", default-features = false }
aes = "0.8"
```

(Verify the current major versions on docs.rs first. `blake3` with `default-features = false` still exposes `derive_key`. `aes` 0.8 exposes the RustCrypto `cipher` block traits.)

- [ ] **Step 2: Add optional deps + feature to `core/Cargo.toml`**

In `[dependencies]`:

```toml
blake3 = { workspace = true, optional = true }
aes = { workspace = true, optional = true }
```

In `[features]`:

```toml
# Shadowsocks 2022 (SIP022) transport (ADR 0009): a pre-shared-key AEAD tunnel interoperable with
# deployed shadowsocks-rust servers. `ring` provides the AEADs; `blake3` derives session subkeys and
# `aes` provides the raw block cipher for the UDP separate-header. Off by default so the base build
# stays rustls/ring-only and cmake-free. See docs/shadowsocks-design.md.
shadowsocks = ["dep:blake3", "dep:aes"]
```

- [ ] **Step 3: Create the module skeleton**

`core/src/transport/shadowsocks/mod.rs`:

```rust
//! Shadowsocks 2022 (SIP022) transport (ADR 0009): a pre-shared-key AEAD tunnel, wire-interoperable
//! with deployed shadowsocks-rust / sing-box SS-2022 servers. TCP (three `2022-blake3-*` ciphers) +
//! UDP (the two AES methods). See `docs/shadowsocks-design.md`.

mod crypto;
mod tcp;
mod udp;
```

`core/src/transport/shadowsocks/crypto.rs`, `tcp.rs`, `udp.rs`: each starts with a one-line `//!` doc comment and is otherwise empty for now:

```rust
//! SS-2022 crypto: base64 PSK decode, BLAKE3 subkey derivation, ring AEAD, raw-AES block.
```
```rust
//! SS-2022 TCP: request/response codec + the AsyncRead+AsyncWrite chunk-framing stream.
```
```rust
//! SS-2022 UDP: native packet build/parse + sliding-window replay filter.
```

In `core/src/transport/mod.rs`, next to the `samizdat` gate, add:

```rust
/// Shadowsocks 2022 transport (ADR 0009): a pre-shared-key AEAD tunnel interoperable with deployed
/// shadowsocks-rust servers. Behind the `shadowsocks` feature so the base build pulls neither
/// `blake3` nor `aes`.
#[cfg(feature = "shadowsocks")]
pub mod shadowsocks;
```

- [ ] **Step 4: Verify it builds with and without the feature**

Run: `cargo build -p spark-core && cargo build -p spark-core --features shadowsocks`
Expected: both clean (empty modules; `dead_code` is fine for now — no `-D warnings` yet on this scaffold step).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml core/Cargo.toml core/src/transport/mod.rs core/src/transport/shadowsocks/
git commit -m "feat(shadowsocks): cargo feature + module skeleton"
```

---

## Task 3: crypto.rs — PSK base64 decode, BLAKE3 subkey, nonce counter

**Files:**
- Modify: `core/src/transport/shadowsocks/crypto.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SsMethod;

    #[test]
    fn decode_psk_validates_length() {
        // "c29tZS0xNi1ieXRlLWtleQ==" decodes to "some-16-byte-key" (16 bytes).
        let psk = decode_psk(SsMethod::Aes128Gcm, "c29tZS0xNi1ieXRlLWtleQ==").unwrap();
        assert_eq!(psk, b"some-16-byte-key");
        // Wrong length for the method is rejected.
        assert!(decode_psk(SsMethod::Aes256Gcm, "c29tZS0xNi1ieXRlLWtleQ==").is_err());
        // Non-base64 is rejected.
        assert!(decode_psk(SsMethod::Aes128Gcm, "not valid base64!!!").is_err());
    }

    #[test]
    fn subkey_is_deterministic_and_method_sized() {
        let psk = [7u8; 32];
        let salt = [9u8; 32];
        let k1 = session_subkey(SsMethod::Aes256Gcm, &psk, &salt);
        let k2 = session_subkey(SsMethod::Aes256Gcm, &psk, &salt);
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
        // A 16-byte method truncates the 32-byte BLAKE3 output to 16.
        let k128 = session_subkey(SsMethod::Aes128Gcm, &[7u8; 16], &[9u8; 16]);
        assert_eq!(k128.len(), 16);
    }

    #[test]
    fn nonce_counter_increments_little_endian() {
        let mut c = NonceCounter::new();
        assert_eq!(c.next(), [0u8; 12]);
        let mut want = [0u8; 12];
        want[0] = 1;
        assert_eq!(c.next(), want);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::crypto`
Expected: FAIL — functions not defined.

- [ ] **Step 3: Implement**

```rust
use crate::config::SsMethod;

/// Errors from SS-2022 crypto setup.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("password is not valid base64")]
    BadBase64,
    #[error("decoded PSK is {got} bytes but method {method:?} needs {want}")]
    KeyLength {
        method: SsMethod,
        got: usize,
        want: usize,
    },
}

/// Decode the base64 PSK and check its length matches the method (SIP022 §2.1).
pub fn decode_psk(method: SsMethod, password: &str) -> Result<Vec<u8>, CryptoError> {
    let psk = base64_decode(password).ok_or(CryptoError::BadBase64)?;
    let want = method.key_len();
    if psk.len() != want {
        return Err(CryptoError::KeyLength {
            method,
            got: psk.len(),
            want,
        });
    }
    Ok(psk)
}

/// Standard base64 decode (RFC 4648, with `=` padding). Hand-rolled to avoid a dependency, matching
/// the repo's hand-rolled-codec convention (cf. the DNS codec, `decode_hex_n`).
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s = s.trim().as_bytes();
    if s.is_empty() || s.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks(4) {
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut acc = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            let v = if c == b'=' {
                if i < 4 - pad {
                    return None; // '=' before the padding region
                }
                0
            } else {
                val(c)?
            };
            acc = (acc << 6) | v as u32;
        }
        out.push((acc >> 16) as u8);
        if pad < 2 {
            out.push((acc >> 8) as u8);
        }
        if pad < 1 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

/// Derive the per-session subkey: `blake3::derive_key(context, PSK ‖ salt)`, truncated to the
/// method's key length (SIP022 §2.2).
pub fn session_subkey(method: SsMethod, psk: &[u8], salt: &[u8]) -> Vec<u8> {
    const CONTEXT: &str = "shadowsocks 2022 session subkey";
    let mut key_material = Vec::with_capacity(psk.len() + salt.len());
    key_material.extend_from_slice(psk);
    key_material.extend_from_slice(salt);
    let full = blake3::derive_key(CONTEXT, &key_material); // [u8; 32]
    full[..method.key_len()].to_vec()
}

/// A 96-bit little-endian AEAD nonce counter, incremented after each seal/open (SIP022 §3.1.1).
pub struct NonceCounter([u8; 12]);

impl NonceCounter {
    pub fn new() -> Self {
        NonceCounter([0u8; 12])
    }
    /// Return the current nonce, then increment the little-endian counter for next time.
    pub fn next(&mut self) -> [u8; 12] {
        let nonce = self.0;
        for byte in self.0.iter_mut() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        nonce
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::crypto`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src/transport/shadowsocks/crypto.rs
git commit -m "feat(shadowsocks): PSK decode, BLAKE3 subkey, nonce counter"
```

---

## Task 4: crypto.rs — ring AEAD `Cipher` + raw AES block

**Files:**
- Modify: `core/src/transport/shadowsocks/crypto.rs`

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn aead_seal_open_round_trips() {
        let key = vec![3u8; 32];
        let cipher = Cipher::new(SsMethod::Aes256Gcm, &key).unwrap();
        let nonce = [1u8; 12];
        let mut buf = b"hello shadowsocks".to_vec();
        cipher.seal(nonce, &mut buf);
        assert_eq!(buf.len(), b"hello shadowsocks".len() + 16); // + tag
        let plain = cipher.open(nonce, &mut buf).unwrap();
        assert_eq!(plain, b"hello shadowsocks");
    }

    #[test]
    fn aead_open_rejects_tampering() {
        let key = vec![3u8; 32];
        let cipher = Cipher::new(SsMethod::Aes256Gcm, &key).unwrap();
        let mut buf = b"data".to_vec();
        cipher.seal([0u8; 12], &mut buf);
        buf[0] ^= 0xff;
        assert!(cipher.open([0u8; 12], &mut buf).is_err());
    }

    #[test]
    fn aes_block_round_trips_fips197_vector() {
        // FIPS-197 AES-128 example: key 000102..0f, plaintext 00112233..ff, ciphertext 69c4e0d8...
        let key = (0u8..16).collect::<Vec<u8>>();
        let block = AesBlock::new(&key).unwrap();
        let mut b = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        block.encrypt(&mut b);
        assert_eq!(
            b,
            [
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a
            ]
        );
        block.decrypt(&mut b);
        assert_eq!(b[0], 0x00);
        assert_eq!(b[15], 0xff);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::crypto`
Expected: FAIL — `Cipher` / `AesBlock` not defined.

- [ ] **Step 3: Implement**

Add to `crypto.rs` (the in-repo ring idiom is `wasm/mod.rs:710-750`; SS-2022 uses **empty AAD**):

```rust
use ring::aead;

/// An SS-2022 AEAD keyed by a session subkey. The caller supplies the nonce per operation (SS uses a
/// counter, not a `NonceSequence`), so `ring::aead::LessSafeKey` is the right primitive.
pub struct Cipher(aead::LessSafeKey);

impl Cipher {
    /// Build the AEAD for `method` from `key` (the session subkey; must be `method.key_len()` bytes).
    pub fn new(method: SsMethod, key: &[u8]) -> Result<Self, CryptoError> {
        let alg: &'static aead::Algorithm = match method {
            SsMethod::Aes128Gcm => &aead::AES_128_GCM,
            SsMethod::Aes256Gcm => &aead::AES_256_GCM,
            SsMethod::Chacha20Poly1305 => &aead::CHACHA20_POLY1305,
        };
        let unbound = aead::UnboundKey::new(alg, key).map_err(|_| CryptoError::KeyLength {
            method,
            got: key.len(),
            want: method.key_len(),
        })?;
        Ok(Cipher(aead::LessSafeKey::new(unbound)))
    }

    /// Seal in place: `buf` becomes ciphertext ‖ 16-byte tag.
    pub fn seal(&self, nonce: [u8; 12], buf: &mut Vec<u8>) {
        // Empty AAD; nonce uniqueness is the caller's contract (counter or packet-derived).
        self.0
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::empty(),
                buf,
            )
            .expect("ring seal never fails for valid key/nonce"); // infallible per ring docs
    }

    /// Open in place: `buf` is ciphertext ‖ tag; returns the plaintext slice on success.
    pub fn open<'a>(&self, nonce: [u8; 12], buf: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        self.0
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::empty(),
                buf,
            )
            .map_err(|_| CryptoError::Auth)
    }
}

/// A raw AES block cipher keyed by the PSK directly — used only for the SS-2022 UDP separate-header
/// (a single ECB block; SIP022 §3.2.1). AES methods only.
pub struct AesBlock(AesKind);

enum AesKind {
    A128(aes::Aes128),
    A256(aes::Aes256),
}

impl AesBlock {
    /// Build from a 16- or 32-byte key.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        use aes::cipher::KeyInit;
        match key.len() {
            16 => Ok(AesBlock(AesKind::A128(aes::Aes128::new(key.into())))),
            32 => Ok(AesBlock(AesKind::A256(aes::Aes256::new(key.into())))),
            n => Err(CryptoError::KeyLength {
                method: SsMethod::Aes128Gcm,
                got: n,
                want: 16,
            }),
        }
    }

    /// Encrypt the 16-byte block in place.
    pub fn encrypt(&self, block: &mut [u8; 16]) {
        use aes::cipher::BlockEncrypt;
        let b = aes::cipher::generic_array::GenericArray::from_mut_slice(block);
        match &self.0 {
            AesKind::A128(c) => c.encrypt_block(b),
            AesKind::A256(c) => c.encrypt_block(b),
        }
    }

    /// Decrypt the 16-byte block in place.
    pub fn decrypt(&self, block: &mut [u8; 16]) {
        use aes::cipher::BlockDecrypt;
        let b = aes::cipher::generic_array::GenericArray::from_mut_slice(block);
        match &self.0 {
            AesKind::A128(c) => c.decrypt_block(b),
            AesKind::A256(c) => c.decrypt_block(b),
        }
    }
}
```

Add the `Auth` variant to `CryptoError`:

```rust
    #[error("AEAD authentication failed")]
    Auth,
```

> Verify against docs.rs: `aes::cipher::{KeyInit, BlockEncrypt, BlockDecrypt}` trait paths and `generic_array::GenericArray::from_mut_slice` (the `aes` 0.8 re-export). `key.into()` converts `&[u8]` of the right length into the `GenericArray` key — confirm the `From` impl exists or use `GenericArray::from_slice(key)`.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::crypto`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src/transport/shadowsocks/crypto.rs
git commit -m "feat(shadowsocks): ring AEAD Cipher + raw AES block"
```

---

## Task 5: SOCKS address codec (`mod.rs`)

SS-2022 encodes the target as a SOCKS5 address (ATYP + addr + port) in both the TCP variable header and the UDP main header. spark's target is always a `SocketAddr` (an IP from the netstack), so encoding only needs ATYP 1 (IPv4) / 4 (IPv6); decoding tolerates 1/3/4 (the server echoes the same IP).

**Files:**
- Modify: `core/src/transport/shadowsocks/mod.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod addr_tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn socks_addr_v4_round_trips() {
        let addr: SocketAddr = "1.2.3.4:8388".parse().unwrap();
        let mut buf = Vec::new();
        write_socks_addr(&addr, &mut buf);
        assert_eq!(buf[0], 0x01); // ATYP IPv4
        assert_eq!(buf.len(), 1 + 4 + 2);
        let (got, consumed) = read_socks_addr(&buf).unwrap();
        assert_eq!(got, addr);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn socks_addr_v6_round_trips() {
        let addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let mut buf = Vec::new();
        write_socks_addr(&addr, &mut buf);
        assert_eq!(buf[0], 0x04); // ATYP IPv6
        let (got, consumed) = read_socks_addr(&buf).unwrap();
        assert_eq!(got, addr);
        assert_eq!(consumed, 1 + 16 + 2);
    }

    #[test]
    fn read_socks_addr_rejects_truncated() {
        assert!(read_socks_addr(&[0x01, 1, 2]).is_none());
        assert!(read_socks_addr(&[]).is_none());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::addr`
Expected: FAIL — functions not defined.

- [ ] **Step 3: Implement**

In `mod.rs`:

```rust
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// Append `addr` in SOCKS5 address format: ATYP(1) ‖ address ‖ port(u16be). spark only ever sends an
/// IP target, so only ATYP 1 (IPv4) and 4 (IPv6) are produced (SIP022 §3.1.3 / RFC 1928 §5).
pub(super) fn write_socks_addr(addr: &SocketAddr, out: &mut Vec<u8>) {
    match addr {
        SocketAddr::V4(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

/// Parse a SOCKS5 address from the front of `buf`, returning the address and bytes consumed.
/// Returns `None` if truncated or the ATYP is a domain (`0x03`) — the server echoes the IP we sent,
/// so we never expect a domain on the response path.
pub(super) fn read_socks_addr(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    let atyp = *buf.first()?;
    match atyp {
        0x01 => {
            // 1 + 4 + 2
            let bytes: [u8; 4] = buf.get(1..5)?.try_into().ok()?;
            let port = u16::from_be_bytes(buf.get(5..7)?.try_into().ok()?);
            Some((SocketAddr::new(Ipv4Addr::from(bytes).into(), port), 7))
        }
        0x04 => {
            let bytes: [u8; 16] = buf.get(1..17)?.try_into().ok()?;
            let port = u16::from_be_bytes(buf.get(17..19)?.try_into().ok()?);
            Some((SocketAddr::new(Ipv6Addr::from(bytes).into(), port), 19))
        }
        _ => None,
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::addr`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src/transport/shadowsocks/mod.rs
git commit -m "feat(shadowsocks): SOCKS5 address codec"
```

---

## Task 6: tcp.rs — request encoder

Builds the request prefix: `salt ‖ enc[fixed header] ‖ enc[variable header]`, written in one socket write (SIP022 §3.1.2/§3.1.3). Fixed header = `type(0) ‖ timestamp(u64be) ‖ length(u16be)`; variable header = `SOCKS addr ‖ padding_len(u16be) ‖ padding`. We always send non-zero random padding and no initial payload (simplest; spec-allowed).

**Files:**
- Modify: `core/src/transport/shadowsocks/tcp.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SsMethod;
    use crate::transport::shadowsocks::crypto::{session_subkey, Cipher, NonceCounter};
    use std::net::SocketAddr;

    #[test]
    fn request_prefix_decodes_back() {
        let method = SsMethod::Aes256Gcm;
        let psk = vec![5u8; 32];
        let target: SocketAddr = "1.2.3.4:443".parse().unwrap();

        let req = encode_request(method, &psk, &target).unwrap();

        // Pull the salt off the front, derive the subkey, and decrypt the two header chunks.
        let salt = &req.bytes[..method.salt_len()];
        let subkey = session_subkey(method, &psk, salt);
        let cipher = Cipher::new(method, &subkey).unwrap();
        let mut ctr = NonceCounter::new();
        let mut off = method.salt_len();

        // Fixed header chunk: 11 bytes plaintext + 16 tag.
        let mut fixed = req.bytes[off..off + 11 + 16].to_vec();
        let fixed = cipher.open(ctr.next(), &mut fixed).unwrap().to_vec();
        assert_eq!(fixed[0], 0); // type = client stream
        let var_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
        off += 11 + 16;

        // Variable header chunk: var_len plaintext + 16 tag.
        let mut var = req.bytes[off..off + var_len + 16].to_vec();
        let var = cipher.open(ctr.next(), &mut var).unwrap();
        assert_eq!(var[0], 0x01); // ATYP IPv4
        // It ends with non-zero padding (we sent no initial payload).
        assert_eq!(off + var_len + 16, req.bytes.len());
        assert_eq!(req.salt, salt.to_vec());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::tcp::tests::request_prefix`
Expected: FAIL — `encode_request` not defined.

- [ ] **Step 3: Implement**

```rust
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use ring::rand::{SecureRandom, SystemRandom};

use crate::config::SsMethod;
use crate::transport::shadowsocks::crypto::{session_subkey, Cipher, CryptoError, NonceCounter};
use crate::transport::shadowsocks::{read_socks_addr, write_socks_addr};

const HEADER_TYPE_CLIENT: u8 = 0;
const HEADER_TYPE_SERVER: u8 = 1;

/// The encoded request prefix plus the salt + send-side cipher/counter the stream keeps using.
pub struct Request {
    pub bytes: Vec<u8>,
    pub salt: Vec<u8>,
    pub cipher: Cipher,
    pub counter: NonceCounter,
}

/// Current Unix time in seconds (SIP022 timestamps). Mirrors samizdat/session_id.rs.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build the SS-2022 request prefix: `salt ‖ enc[fixed header] ‖ enc[variable header]`.
pub fn encode_request(
    method: SsMethod,
    psk: &[u8],
    target: &SocketAddr,
) -> Result<Request, CryptoError> {
    let rng = SystemRandom::new();

    // Random per-stream salt.
    let mut salt = vec![0u8; method.salt_len()];
    rng.fill(&mut salt).map_err(|_| CryptoError::BadBase64)?; // RNG failure → reuse error sentinel
    let subkey = session_subkey(method, psk, &salt);
    let cipher = Cipher::new(method, &subkey)?;
    let mut counter = NonceCounter::new();

    // Variable-length header plaintext: SOCKS addr ‖ padding_len(u16be) ‖ padding.
    let mut var = Vec::with_capacity(19 + 16);
    write_socks_addr(target, &mut var);
    // Random padding 1..=64 bytes (non-zero; we send no initial payload).
    let mut pad_byte = [0u8; 1];
    rng.fill(&mut pad_byte).map_err(|_| CryptoError::BadBase64)?;
    let pad_len = (pad_byte[0] % 64) as u16 + 1;
    var.extend_from_slice(&pad_len.to_be_bytes());
    let mut padding = vec![0u8; pad_len as usize];
    rng.fill(&mut padding).map_err(|_| CryptoError::BadBase64)?;
    var.extend_from_slice(&padding);

    // Fixed-length header plaintext (11 bytes): type ‖ timestamp ‖ length(of var).
    let mut fixed = Vec::with_capacity(11);
    fixed.push(HEADER_TYPE_CLIENT);
    fixed.extend_from_slice(&now_secs().to_be_bytes());
    fixed.extend_from_slice(&(var.len() as u16).to_be_bytes());

    // Seal both chunks with consecutive counter nonces; concatenate after the salt.
    let mut bytes = Vec::with_capacity(salt.len() + fixed.len() + var.len() + 32);
    bytes.extend_from_slice(&salt);
    cipher.seal(counter.next(), &mut fixed);
    bytes.extend_from_slice(&fixed);
    cipher.seal(counter.next(), &mut var);
    bytes.extend_from_slice(&var);

    Ok(Request {
        bytes,
        salt,
        cipher,
        counter,
    })
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::tcp::tests::request_prefix`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src/transport/shadowsocks/tcp.rs
git commit -m "feat(shadowsocks): TCP request encoder"
```

---

## Task 7: tcp.rs — response head decoder + validation

Parses the response: `salt ‖ enc[fixed header]` where the fixed header is `type(1) ‖ timestamp(u64be) ‖ request_salt(salt_len) ‖ length(u16be)`. Validates type, timestamp window (±30 s), and that `request_salt` equals our request salt (SIP022 §3.1.3). Returns the response-side cipher/counter and the first payload chunk's length.

**Files:**
- Modify: `core/src/transport/shadowsocks/tcp.rs`

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn response_head_validates_request_salt() {
        let method = SsMethod::Aes256Gcm;
        let psk = vec![5u8; 32];
        let request_salt = vec![5u8; 32];

        // Build a server response head the way a server would.
        let rng = ring::rand::SystemRandom::new();
        let mut resp_salt = vec![0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut resp_salt).unwrap();
        let subkey = session_subkey(method, &psk, &resp_salt);
        let cipher = Cipher::new(method, &subkey).unwrap();
        let mut ctr = NonceCounter::new();
        let mut fixed = Vec::new();
        fixed.push(1u8); // server stream
        fixed.extend_from_slice(&now_secs().to_be_bytes());
        fixed.extend_from_slice(&request_salt); // echoes our salt
        fixed.extend_from_slice(&77u16.to_be_bytes()); // first payload length
        cipher.seal(ctr.next(), &mut fixed);
        let mut wire = resp_salt.clone();
        wire.extend_from_slice(&fixed);

        let head = decode_response_head(method, &psk, &request_salt, &wire).unwrap();
        assert_eq!(head.first_chunk_len, 77);

        // A wrong request_salt is rejected.
        let bad_salt = vec![9u8; 32];
        assert!(decode_response_head(method, &psk, &bad_salt, &wire).is_err());
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::tcp::tests::response_head`
Expected: FAIL.

- [ ] **Step 3: Implement**

```rust
/// Decoded response head: the response-side cipher/counter (for subsequent chunks) and the length of
/// the first payload chunk (the fixed header doubles as the first length chunk).
pub struct ResponseHead {
    pub cipher: Cipher,
    pub counter: NonceCounter,
    pub first_chunk_len: usize,
}

/// Maximum tolerated clock skew on a timestamp (SIP022 §3.1.3).
const MAX_SKEW_SECS: u64 = 30;

/// The number of `salt ‖ enc[fixed header]` bytes for a response (`salt + 1 + 8 + salt + 2 + 16`).
pub fn response_head_len(method: SsMethod) -> usize {
    let sl = method.salt_len();
    sl + (1 + 8 + sl + 2) + 16
}

/// Parse and validate the response head from `wire` (exactly `response_head_len(method)` bytes).
pub fn decode_response_head(
    method: SsMethod,
    psk: &[u8],
    request_salt: &[u8],
    wire: &[u8],
) -> Result<ResponseHead, CryptoError> {
    let sl = method.salt_len();
    if wire.len() < response_head_len(method) {
        return Err(CryptoError::Auth); // too short to be a valid head
    }
    let resp_salt = &wire[..sl];
    let subkey = session_subkey(method, psk, resp_salt);
    let cipher = Cipher::new(method, &subkey)?;
    let mut counter = NonceCounter::new();

    let mut fixed = wire[sl..sl + (1 + 8 + sl + 2) + 16].to_vec();
    let fixed = cipher.open(counter.next(), &mut fixed)?.to_vec();

    if fixed[0] != HEADER_TYPE_SERVER {
        return Err(CryptoError::Auth);
    }
    let ts = u64::from_be_bytes(fixed[1..9].try_into().map_err(|_| CryptoError::Auth)?);
    let now = now_secs();
    if now.abs_diff(ts) > MAX_SKEW_SECS {
        return Err(CryptoError::Auth);
    }
    if &fixed[9..9 + sl] != request_salt {
        return Err(CryptoError::Auth);
    }
    let len_off = 9 + sl;
    let first_chunk_len =
        u16::from_be_bytes(fixed[len_off..len_off + 2].try_into().map_err(|_| CryptoError::Auth)?)
            as usize;

    Ok(ResponseHead {
        cipher,
        counter,
        first_chunk_len,
    })
}
```

> The error type is reused (`CryptoError::Auth`) for all rejection reasons here to keep one error surface; if richer diagnostics are wanted later, split it. Do **not** leak which check failed to a remote peer (probe-resistance).

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::tcp::tests::response_head`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src/transport/shadowsocks/tcp.rs
git commit -m "feat(shadowsocks): TCP response head decoder + validation"
```

---

## Task 8: tcp.rs — `ShadowsocksStream` (chunk framing + AsyncRead/AsyncWrite)

The `BoxedStream` returned by `dial()`. Owns the `TcpStream`; on first read it consumes the response head, then frames length+payload AEAD chunks. Manual `poll_read`/`poll_write` (the in-repo idiom is `tcp_tunnel/stream.rs`), driven by cancel-safe `poll_read` into a `BytesMut`.

**Files:**
- Modify: `core/src/transport/shadowsocks/tcp.rs`

- [ ] **Step 1: Write the failing test** (full client⇄in-memory-SS-peer round trip via `tokio::io::duplex`)

```rust
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    /// A minimal in-test SS-2022 server half: reads a request, then echoes payload back through the
    /// response framing. Proves the client stream interops with a spec-correct peer.
    async fn ss_echo_peer(mut sock: tokio::io::DuplexStream, method: SsMethod, psk: Vec<u8>) {
        // Read salt + both header chunks. (Sizes are deterministic given the method; the var-header
        // length is in the fixed header.) For the test, read generously then parse.
        let sl = method.salt_len();
        let mut head = vec![0u8; sl + 11 + 16];
        sock.read_exact(&mut head).await.unwrap();
        let req_salt = head[..sl].to_vec();
        let subkey = session_subkey(method, &psk, &req_salt);
        let rx = Cipher::new(method, &subkey).unwrap();
        let mut rxc = NonceCounter::new();
        let mut fixed = head[sl..].to_vec();
        let fixed = rx.open(rxc.next(), &mut fixed).unwrap().to_vec();
        let var_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
        let mut var = vec![0u8; var_len + 16];
        sock.read_exact(&mut var).await.unwrap();
        rx.open(rxc.next(), &mut var).unwrap();

        // Send the response head (echo request_salt) + one payload chunk "pong".
        let rng = ring::rand::SystemRandom::new();
        let mut resp_salt = vec![0u8; sl];
        ring::rand::SecureRandom::fill(&rng, &mut resp_salt).unwrap();
        let tx = Cipher::new(method, &session_subkey(method, &psk, &resp_salt)).unwrap();
        let mut txc = NonceCounter::new();
        let payload = b"pong";
        let mut hdr = vec![1u8];
        hdr.extend_from_slice(&now_secs().to_be_bytes());
        hdr.extend_from_slice(&req_salt);
        hdr.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        tx.seal(txc.next(), &mut hdr);
        let mut body = payload.to_vec();
        tx.seal(txc.next(), &mut body);
        let mut out = resp_salt;
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&body);
        sock.write_all(&out).await.unwrap();
        sock.flush().await.unwrap();
    }

    #[tokio::test]
    async fn stream_round_trips_against_a_spec_peer() {
        let method = SsMethod::Aes256Gcm;
        let psk = vec![5u8; 32];
        let target: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let (client_io, server_io) = duplex(64 * 1024);
        let peer = tokio::spawn(ss_echo_peer(server_io, method, psk.clone()));

        // Build the request, write it, wrap the io in a ShadowsocksStream.
        let req = encode_request(method, &psk, &target).unwrap();
        let mut stream = ShadowsocksStream::new(client_io, method, psk.clone(), req);
        stream.write_all(b"ping").await.unwrap(); // app upload (not asserted by the echo peer)
        stream.flush().await.unwrap();

        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        peer.await.unwrap();
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::tcp::tests::stream_round_trips`
Expected: FAIL — `ShadowsocksStream` not defined.

- [ ] **Step 3: Implement**

```rust
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::config::SsMethod;

/// The largest plaintext payload per chunk (SIP022 §3.1.2 raised the cap to 0xFFFF).
const MAX_PAYLOAD: usize = 0xFFFF;
const TAG: usize = 16;

/// Read-side state machine over the encrypted chunk stream.
enum RxState {
    /// Haven't consumed the response head yet.
    NeedHead,
    /// Need the next encrypted length chunk (2 + tag) — except the very first, whose length came
    /// from the response head.
    NeedLen,
    /// Need an encrypted payload chunk of `plain` plaintext bytes (`plain + tag` on the wire).
    NeedPayload { plain: usize },
}

/// An SS-2022 TCP stream: a transparent `AsyncRead+AsyncWrite` over the encrypted chunk framing.
pub struct ShadowsocksStream<S> {
    inner: S,
    method: SsMethod,
    psk: Vec<u8>,
    // send side (request salt already written by the caller)
    tx: Cipher,
    tx_ctr: NonceCounter,
    tx_pending: BytesMut, // encrypted bytes not yet flushed to `inner`
    // receive side
    rx: Option<ResponseHead>, // None until the head is consumed
    rx_state: RxState,
    rx_raw: BytesMut,   // bytes read from `inner`, not yet decrypted
    rx_plain: BytesMut, // decrypted payload ready for the caller
    request_salt: Vec<u8>,
}

impl<S> ShadowsocksStream<S> {
    /// Wrap `inner` after the request prefix in `req` has been (or will be) written. Takes ownership
    /// of the send-side cipher/counter from `req`.
    pub fn new(inner: S, method: SsMethod, psk: Vec<u8>, req: Request) -> Self {
        let mut tx_pending = BytesMut::with_capacity(req.bytes.len());
        tx_pending.extend_from_slice(&req.bytes); // flush the request prefix on first poll_write/flush
        ShadowsocksStream {
            inner,
            method,
            psk,
            tx: req.cipher,
            tx_ctr: req.counter,
            tx_pending,
            rx: None,
            rx_state: RxState::NeedHead,
            rx_raw: BytesMut::with_capacity(16 * 1024),
            rx_plain: BytesMut::with_capacity(16 * 1024),
            request_salt: req.salt,
        }
    }
}

impl<S: AsyncRead + Unpin> ShadowsocksStream<S> {
    /// Pull at least `want` raw bytes into `rx_raw`, returning `Pending`/`Err`/`Ok(false=EOF)`.
    fn fill_raw(&mut self, cx: &mut Context<'_>, want: usize) -> Poll<io::Result<bool>> {
        while self.rx_raw.len() < want {
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(false)); // EOF
                    }
                    self.rx_raw.extend_from_slice(rb.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(true))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ShadowsocksStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            // Hand back already-decrypted plaintext first.
            if !me.rx_plain.is_empty() {
                let n = me.rx_plain.len().min(buf.remaining());
                buf.put_slice(&me.rx_plain[..n]);
                me.rx_plain.advance(n);
                return Poll::Ready(Ok(()));
            }
            match me.rx_state {
                RxState::NeedHead => {
                    let head_len = response_head_len(me.method);
                    match me.fill_raw(cx, head_len) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())), // EOF before head
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                    let head_bytes = me.rx_raw.split_to(head_len);
                    let head = decode_response_head(me.method, &me.psk, &me.request_salt, &head_bytes)
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ss response head"))?;
                    let first = head.first_chunk_len;
                    me.rx = Some(head);
                    me.rx_state = RxState::NeedPayload { plain: first };
                }
                RxState::NeedLen => {
                    match me.fill_raw(cx, 2 + TAG) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())), // clean EOF
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                    let mut chunk = me.rx_raw.split_to(2 + TAG).to_vec();
                    let head = me.rx.as_mut().expect("head set before NeedLen");
                    let nonce = head.counter.next();
                    let plain = head
                        .cipher
                        .open(nonce, &mut chunk)
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ss len chunk"))?;
                    let plain_len = u16::from_be_bytes([plain[0], plain[1]]) as usize;
                    me.rx_state = RxState::NeedPayload { plain: plain_len };
                }
                RxState::NeedPayload { plain } => {
                    match me.fill_raw(cx, plain + TAG) {
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "ss payload chunk truncated",
                            )))
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                    let mut chunk = me.rx_raw.split_to(plain + TAG).to_vec();
                    let head = me.rx.as_mut().expect("head set before NeedPayload");
                    let nonce = head.counter.next();
                    let payload = head
                        .cipher
                        .open(nonce, &mut chunk)
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ss payload"))?;
                    me.rx_plain.extend_from_slice(payload);
                    me.rx_state = RxState::NeedLen;
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> ShadowsocksStream<S> {
    /// Flush `tx_pending` to `inner`. Returns `Ready(Ok(()))` only when fully drained.
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.tx_pending.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.tx_pending) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ss write zero",
                    )))
                }
                Poll::Ready(Ok(n)) => {
                    self.tx_pending.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ShadowsocksStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        // Drain any pending bytes first (the request prefix, or a prior partial write).
        match me.flush_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Encrypt one chunk (cap at MAX_PAYLOAD): enc[len] ‖ enc[payload].
        let take = buf.len().min(MAX_PAYLOAD);
        let mut len_chunk = (take as u16).to_be_bytes().to_vec();
        me.tx.seal(me.tx_ctr.next(), &mut len_chunk);
        let mut payload = buf[..take].to_vec();
        me.tx.seal(me.tx_ctr.next(), &mut payload);
        me.tx_pending.extend_from_slice(&len_chunk);
        me.tx_pending.extend_from_slice(&payload);
        // Try to push it out now; partial is fine (stays in tx_pending).
        let _ = me.flush_pending(cx);
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match me.flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match me.flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_shutdown(cx),
            other => other,
        }
    }
}
```

Also add `use std::io;` at the top of `tcp.rs` if not already present.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::tcp::tests::stream_round_trips`
Expected: PASS.

- [ ] **Step 5: Add a split-read robustness test** (guards the `NeedLen → NeedPayload` loop + partial `fill_raw` across multiple 0xFFFF-capped chunks)

```rust
    /// A peer that sends a known `blob` after the request head, split into MAX_PAYLOAD-capped chunks.
    async fn ss_blob_peer(
        mut sock: tokio::io::DuplexStream,
        method: SsMethod,
        psk: Vec<u8>,
        blob: Vec<u8>,
    ) {
        let sl = method.salt_len();
        let mut head = vec![0u8; sl + 11 + 16];
        sock.read_exact(&mut head).await.unwrap();
        let req_salt = head[..sl].to_vec();
        let rx = Cipher::new(method, &session_subkey(method, &psk, &req_salt)).unwrap();
        let mut rxc = NonceCounter::new();
        let mut fixed = head[sl..].to_vec();
        let fixed = rx.open(rxc.next(), &mut fixed).unwrap().to_vec();
        let var_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
        let mut var = vec![0u8; var_len + 16];
        sock.read_exact(&mut var).await.unwrap();
        rx.open(rxc.next(), &mut var).unwrap();

        let rng = ring::rand::SystemRandom::new();
        let mut resp_salt = vec![0u8; sl];
        ring::rand::SecureRandom::fill(&rng, &mut resp_salt).unwrap();
        let tx = Cipher::new(method, &session_subkey(method, &psk, &resp_salt)).unwrap();
        let mut txc = NonceCounter::new();
        let mut out = resp_salt;

        // First "chunk" is the response head (its length field = first payload chunk length).
        let mut chunks = blob.chunks(0xFFFF);
        let first = chunks.next().unwrap_or(&[]);
        let mut hdr = vec![1u8];
        hdr.extend_from_slice(&now_secs().to_be_bytes());
        hdr.extend_from_slice(&req_salt);
        hdr.extend_from_slice(&(first.len() as u16).to_be_bytes());
        tx.seal(txc.next(), &mut hdr);
        out.extend_from_slice(&hdr);
        let mut body = first.to_vec();
        tx.seal(txc.next(), &mut body);
        out.extend_from_slice(&body);

        // Remaining chunks as length-chunk + payload-chunk pairs.
        for chunk in chunks {
            let mut len = (chunk.len() as u16).to_be_bytes().to_vec();
            tx.seal(txc.next(), &mut len);
            out.extend_from_slice(&len);
            let mut payload = chunk.to_vec();
            tx.seal(txc.next(), &mut payload);
            out.extend_from_slice(&payload);
        }
        sock.write_all(&out).await.unwrap();
        sock.flush().await.unwrap();
    }

    #[tokio::test]
    async fn stream_handles_a_large_chunked_download() {
        let method = SsMethod::Aes256Gcm;
        let psk = vec![5u8; 32];
        let target: SocketAddr = "1.2.3.4:443".parse().unwrap();
        // 200 KiB forces 4 chunks (0xFFFF cap) and many partial reads through the duplex.
        let blob: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();

        let (client_io, server_io) = duplex(8 * 1024); // small duplex => lots of partial reads
        let peer = tokio::spawn(ss_blob_peer(server_io, method, psk.clone(), blob.clone()));

        let req = encode_request(method, &psk, &target).unwrap();
        let mut stream = ShadowsocksStream::new(client_io, method, psk.clone(), req);
        stream.flush().await.unwrap(); // push the request prefix

        let mut got = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&chunk[..n]);
            if got.len() == blob.len() {
                break;
            }
        }
        assert_eq!(got, blob);
        peer.await.unwrap();
    }
```

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::tcp::tests::stream_handles_a_large`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add core/src/transport/shadowsocks/tcp.rs
git commit -m "feat(shadowsocks): ShadowsocksStream (TCP chunk framing)"
```

---

## Task 9: udp.rs — sliding-window replay filter

WireGuard-style filter: accept strictly-increasing packet IDs and any within a 64-bit window behind the highest seen; reject duplicates and too-old IDs (SIP022 §3.2.4).

**Files:**
- Modify: `core/src/transport/shadowsocks/udp.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_accepts_in_order_and_rejects_replays() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0));
        assert!(w.accept(1));
        assert!(w.accept(2));
        assert!(!w.accept(1)); // replay
        assert!(w.accept(100)); // jump forward
        assert!(!w.accept(100)); // replay of the new max
        assert!(w.accept(99)); // within window, not yet seen
        assert!(!w.accept(0)); // far behind the window now -> rejected
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::udp::tests::window`
Expected: FAIL.

- [ ] **Step 3: Implement**

```rust
/// Size of the replay window (bits behind the highest accepted packet ID).
const WINDOW: u64 = 64;

/// A sliding-window replay filter over u64 packet IDs (SIP022 §3.2.4).
pub struct ReplayWindow {
    highest: u64,
    bitmap: u64, // bit i set => (highest - i) was seen
    seen_any: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        ReplayWindow {
            highest: 0,
            bitmap: 0,
            seen_any: false,
        }
    }

    /// Check `id`: returns true if it is fresh (and records it), false if duplicate/out-of-window.
    pub fn accept(&mut self, id: u64) -> bool {
        if !self.seen_any {
            self.seen_any = true;
            self.highest = id;
            self.bitmap = 1; // bit 0 = highest seen
            return true;
        }
        if id > self.highest {
            let shift = id - self.highest;
            self.bitmap = if shift >= 64 { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.highest = id;
            true
        } else {
            let back = self.highest - id;
            if back >= WINDOW {
                return false; // too old
            }
            let mask = 1u64 << back;
            if self.bitmap & mask != 0 {
                false // already seen
            } else {
                self.bitmap |= mask;
                true
            }
        }
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::udp::tests::window`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src/transport/shadowsocks/udp.rs
git commit -m "feat(shadowsocks): UDP sliding-window replay filter"
```

---

## Task 10: udp.rs — client packet build + server packet parse

AES methods only. Build: `enc[sep header] ‖ AES-GCM(subkey, nonce=sep[4..16], main header ‖ payload)`. Parse the inverse, validate type/timestamp/client-session-id, return payload. (SIP022 §3.2.)

**Files:**
- Modify: `core/src/transport/shadowsocks/udp.rs`

- [ ] **Step 1: Write the failing test** (build a client packet, parse it as a server would, and vice versa)

```rust
    use crate::config::SsMethod;
    use crate::transport::shadowsocks::crypto::{session_subkey, AesBlock, Cipher};
    use std::net::SocketAddr;

    #[test]
    fn client_packet_parses_as_a_server_would() {
        let method = SsMethod::Aes256Gcm;
        let psk = vec![5u8; 32];
        let target: SocketAddr = "1.2.3.4:53".parse().unwrap();
        let session_id = [1u8; 8];

        let pkt = build_client_packet(method, &psk, session_id, 0, &target, b"query").unwrap();

        // Server side: AES-ECB-decrypt the header, derive subkey, AES-GCM-open the body.
        let block = AesBlock::new(&psk).unwrap();
        let mut sep = [0u8; 16];
        sep.copy_from_slice(&pkt[..16]);
        block.decrypt(&mut sep);
        assert_eq!(&sep[..8], &session_id);
        let subkey = session_subkey(method, &psk, &sep[..8]);
        let cipher = Cipher::new(method, &subkey).unwrap();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&sep[4..16]);
        let mut body = pkt[16..].to_vec();
        let body = cipher.open(nonce, &mut body).unwrap();
        assert_eq!(body[0], 0); // client packet type
    }

    #[test]
    fn parse_server_packet_round_trips() {
        let method = SsMethod::Aes256Gcm;
        let psk = vec![5u8; 32];
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let client_sid = [2u8; 8];
        let server_sid = [3u8; 8];

        // Build a server->client packet by hand, then parse it.
        let pkt = build_server_packet_for_test(method, &psk, server_sid, 0, client_sid, &target, b"answer");
        let parsed = parse_server_packet(method, &psk, client_sid, &pkt).unwrap();
        assert_eq!(parsed.payload, b"answer");
        assert_eq!(parsed.server_session_id, server_sid);
        assert_eq!(parsed.packet_id, 0);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::udp::tests`
Expected: FAIL.

- [ ] **Step 3: Implement**

```rust
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use ring::rand::{SecureRandom, SystemRandom};

use crate::config::SsMethod;
use crate::transport::shadowsocks::crypto::{session_subkey, AesBlock, Cipher, CryptoError};
use crate::transport::shadowsocks::{read_socks_addr, write_socks_addr};

const PKT_TYPE_CLIENT: u8 = 0;
const PKT_TYPE_SERVER: u8 = 1;
const MAX_SKEW_SECS: u64 = 30;
const TAG: usize = 16;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a client→server UDP packet (AES methods only).
pub fn build_client_packet(
    method: SsMethod,
    psk: &[u8],
    session_id: [u8; 8],
    packet_id: u64,
    target: &SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Separate header: session_id ‖ packet_id(be).
    let mut sep = [0u8; 16];
    sep[..8].copy_from_slice(&session_id);
    sep[8..].copy_from_slice(&packet_id.to_be_bytes());

    // Body plaintext: type ‖ timestamp ‖ padding_len(0) ‖ SOCKS addr ‖ payload.
    let mut body = Vec::with_capacity(1 + 8 + 2 + 19 + payload.len() + TAG);
    body.push(PKT_TYPE_CLIENT);
    body.extend_from_slice(&now_secs().to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes()); // no padding for connected single-target flows
    write_socks_addr(target, &mut body);
    body.extend_from_slice(payload);

    // AEAD the body with the session subkey; nonce = sep[4..16].
    let subkey = session_subkey(method, psk, &session_id);
    let cipher = Cipher::new(method, &subkey)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sep[4..16]);
    cipher.seal(nonce, &mut body);

    // Encrypt the separate header with the PSK-keyed block cipher, then concatenate.
    let block = AesBlock::new(psk)?;
    block.encrypt(&mut sep);
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&sep);
    out.extend_from_slice(&body);
    Ok(out)
}

/// A parsed server→client UDP packet.
pub struct ServerPacket {
    pub server_session_id: [u8; 8],
    pub packet_id: u64,
    pub payload: Vec<u8>,
}

/// Parse and validate a server→client UDP packet (AES methods only). Does NOT advance any replay
/// window — the caller does that after this returns Ok (so invalid packets don't poison the window).
pub fn parse_server_packet(
    method: SsMethod,
    psk: &[u8],
    expected_client_sid: [u8; 8],
    pkt: &[u8],
) -> Result<ServerPacket, CryptoError> {
    if pkt.len() < 16 + TAG {
        return Err(CryptoError::Auth);
    }
    // Decrypt the separate header.
    let block = AesBlock::new(psk)?;
    let mut sep = [0u8; 16];
    sep.copy_from_slice(&pkt[..16]);
    block.decrypt(&mut sep);
    let server_session_id: [u8; 8] = sep[..8].try_into().map_err(|_| CryptoError::Auth)?;
    let packet_id = u64::from_be_bytes(sep[8..].try_into().map_err(|_| CryptoError::Auth)?);

    // Open the body with this server session's subkey.
    let subkey = session_subkey(method, psk, &server_session_id);
    let cipher = Cipher::new(method, &subkey)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sep[4..16]);
    let mut body = pkt[16..].to_vec();
    let body = cipher.open(nonce, &mut body)?.to_vec();

    // Server main header: type ‖ timestamp ‖ client_session_id(8) ‖ padding_len(2) ‖ padding ‖ SOCKS addr ‖ payload.
    if body.first() != Some(&PKT_TYPE_SERVER) {
        return Err(CryptoError::Auth);
    }
    let ts = u64::from_be_bytes(body.get(1..9).ok_or(CryptoError::Auth)?.try_into().unwrap());
    if now_secs().abs_diff(ts) > MAX_SKEW_SECS {
        return Err(CryptoError::Auth);
    }
    let csid = body.get(9..17).ok_or(CryptoError::Auth)?;
    if csid != expected_client_sid {
        return Err(CryptoError::Auth);
    }
    let pad_len = u16::from_be_bytes(body.get(17..19).ok_or(CryptoError::Auth)?.try_into().unwrap())
        as usize;
    let addr_off = 19 + pad_len;
    let (_addr, consumed) =
        read_socks_addr(body.get(addr_off..).ok_or(CryptoError::Auth)?).ok_or(CryptoError::Auth)?;
    let payload = body[addr_off + consumed..].to_vec();

    Ok(ServerPacket {
        server_session_id,
        packet_id,
        payload,
    })
}

/// Test-only: build a server→client packet (mirror of `build_client_packet` with the server header).
#[cfg(test)]
pub fn build_server_packet_for_test(
    method: SsMethod,
    psk: &[u8],
    server_sid: [u8; 8],
    packet_id: u64,
    client_sid: [u8; 8],
    src: &SocketAddr,
    payload: &[u8],
) -> Vec<u8> {
    let mut sep = [0u8; 16];
    sep[..8].copy_from_slice(&server_sid);
    sep[8..].copy_from_slice(&packet_id.to_be_bytes());
    let mut body = Vec::new();
    body.push(PKT_TYPE_SERVER);
    body.extend_from_slice(&now_secs().to_be_bytes());
    body.extend_from_slice(&client_sid);
    body.extend_from_slice(&0u16.to_be_bytes());
    write_socks_addr(src, &mut body);
    body.extend_from_slice(payload);
    let subkey = session_subkey(method, psk, &server_sid);
    let cipher = Cipher::new(method, &subkey).unwrap();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sep[4..16]);
    cipher.seal(nonce, &mut body);
    let block = AesBlock::new(psk).unwrap();
    block.encrypt(&mut sep);
    let mut out = sep.to_vec();
    out.extend_from_slice(&body);
    out
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::udp::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src/transport/shadowsocks/udp.rs
git commit -m "feat(shadowsocks): UDP client/server packet codec"
```

---

## Task 11: udp.rs — `ShadowsocksUdpSink` / `ShadowsocksUdpSource`

The split halves returned by `dial_udp`. Sink owns the connected `UdpSocket` + send-side state (session ID, packet-ID counter); source owns the socket + a per-server-session `ReplayWindow` map.

**Files:**
- Modify: `core/src/transport/shadowsocks/udp.rs`

- [ ] **Step 1: Write the failing test** (a real loopback socket pair: an in-test "server" decrypts a client packet and replies; the source decrypts the reply)

```rust
    use crate::transport::{PacketSink, PacketSource};
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn udp_halves_round_trip_over_loopback() {
        let method = SsMethod::Aes256Gcm;
        let psk = vec![5u8; 32];
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();

        // In-test "server" socket.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        // Client socket connected to the server.
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(server_addr).await.unwrap();
        let client = Arc::new(client);

        let session_id = [7u8; 8];
        let mut sink = ShadowsocksUdpSink::new(Arc::clone(&client), method, psk.clone(), target, session_id);
        let mut source = ShadowsocksUdpSource::new(Arc::clone(&client), method, psk.clone(), session_id);

        // Client sends "ping".
        sink.send(b"ping").await.unwrap();

        // Server receives, decrypts, replies "pong".
        let mut rbuf = [0u8; 2048];
        let (n, from) = server.recv_from(&mut rbuf).await.unwrap();
        let parsed_client =
            // reuse build/parse: decrypt as the server would using build_server_packet_for_test inverse
            super::tests_helpers_parse_client(method, &psk, session_id, &rbuf[..n]);
        assert_eq!(parsed_client, b"ping");
        let reply = build_server_packet_for_test(method, &psk, [8u8; 8], 0, session_id, &target, b"pong");
        server.send_to(&reply, from).await.unwrap();

        // Client source receives "pong".
        let mut buf = [0u8; 2048];
        let n = source.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong");
    }
```

> The test needs a small `tests_helpers_parse_client` that runs the server-side decrypt of a client packet (AES-ECB header + GCM body) and returns the inner payload. Write it in the `tests` module using the already-public `AesBlock`/`Cipher`/`session_subkey` + `read_socks_addr`, mirroring `client_packet_parses_as_a_server_would` from Task 10.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::udp::tests::udp_halves`
Expected: FAIL — sink/source types not defined.

- [ ] **Step 3: Implement**

```rust
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::transport::{PacketSink, PacketSource};

/// Send half of an SS-2022 UDP association (AES methods).
pub struct ShadowsocksUdpSink {
    socket: Arc<UdpSocket>,
    method: SsMethod,
    psk: Vec<u8>,
    target: SocketAddr,
    session_id: [u8; 8],
    packet_id: u64,
}

impl ShadowsocksUdpSink {
    pub fn new(
        socket: Arc<UdpSocket>,
        method: SsMethod,
        psk: Vec<u8>,
        target: SocketAddr,
        session_id: [u8; 8],
    ) -> Self {
        ShadowsocksUdpSink {
            socket,
            method,
            psk,
            target,
            session_id,
            packet_id: 0,
        }
    }
}

#[async_trait]
impl PacketSink for ShadowsocksUdpSink {
    async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        let pkt = build_client_packet(
            self.method,
            &self.psk,
            self.session_id,
            self.packet_id,
            &self.target,
            payload,
        )
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        self.packet_id = self.packet_id.wrapping_add(1);
        self.socket.send(&pkt).await.map(|_| ())
    }
}

/// Receive half of an SS-2022 UDP association (AES methods).
pub struct ShadowsocksUdpSource {
    socket: Arc<UdpSocket>,
    method: SsMethod,
    psk: Vec<u8>,
    client_session_id: [u8; 8],
    windows: HashMap<[u8; 8], ReplayWindow>,
}

impl ShadowsocksUdpSource {
    pub fn new(
        socket: Arc<UdpSocket>,
        method: SsMethod,
        psk: Vec<u8>,
        client_session_id: [u8; 8],
    ) -> Self {
        ShadowsocksUdpSource {
            socket,
            method,
            psk,
            client_session_id,
            windows: HashMap::new(),
        }
    }
}

#[async_trait]
impl PacketSource for ShadowsocksUdpSource {
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Loop until a valid, non-replayed packet arrives (drop and keep reading otherwise, so one
        // bad datagram doesn't surface as an error to the netstack).
        let mut raw = vec![0u8; 64 * 1024];
        loop {
            let n = self.socket.recv(&mut raw).await?;
            let parsed =
                match parse_server_packet(self.method, &self.psk, self.client_session_id, &raw[..n]) {
                    Ok(p) => p,
                    Err(_) => continue, // malformed / failed auth -> drop
                };
            // Replay check, advancing the window only now (after full validation).
            let window = self
                .windows
                .entry(parsed.server_session_id)
                .or_insert_with(ReplayWindow::new);
            if !window.accept(parsed.packet_id) {
                continue; // replay / out-of-window -> drop
            }
            let len = parsed.payload.len().min(buf.len());
            buf[..len].copy_from_slice(&parsed.payload[..len]);
            return Ok(len);
        }
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::udp::tests::udp_halves`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src/transport/shadowsocks/udp.rs
git commit -m "feat(shadowsocks): UDP sink/source halves"
```

---

## Task 12: mod.rs — `ShadowsocksTransport` (impl `Transport` + `UdpTransport`)

Ties it together: `dial` opens an SS connection and returns a `ShadowsocksStream`; `dial_udp` opens a connected UDP socket and returns the two halves (erroring for the chacha method). Reuses `protected_tcp_connect` / `protected_udp_socket`.

**Files:**
- Modify: `core/src/transport/shadowsocks/mod.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod transport_tests {
    use super::*;
    use crate::config::SsMethod;
    use crate::transport::{Transport, UdpTransport};

    #[tokio::test]
    async fn dial_udp_rejects_chacha_method() {
        let t = ShadowsocksTransport::new(
            "127.0.0.1:1".parse().unwrap(),
            SsMethod::Chacha20Poly1305,
            vec![0u8; 32],
            None,
        );
        let target = "1.2.3.4:53".parse().unwrap();
        let err = t.dial_udp(target).await.err().expect("chacha udp must error");
        assert!(err.to_string().contains("UDP"));
    }
}
```

(A full `dial` test against a live server is the interop gate, Task 14 — not a unit test here.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::transport_tests`
Expected: FAIL — `ShadowsocksTransport` not defined.

- [ ] **Step 3: Implement**

In `mod.rs`, make the submodule items reachable and add the transport. First adjust the module decls + re-exports at the top:

```rust
mod crypto;
mod tcp;
mod udp;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::UdpSocket;

use crate::config::SsMethod;
use crate::net::SocketProtector;
use crate::transport::{
    protected_tcp_connect, protected_udp_socket, BoxedPacketSink, BoxedPacketSource, BoxedStream,
    Transport, UdpTransport,
};
use crypto::decode_psk;
use tcp::{encode_request, ShadowsocksStream};
use udp::{ShadowsocksUdpSink, ShadowsocksUdpSource};
```

Then the transport:

```rust
/// An SS-2022 transport: dials the SS server per flow (TCP 1:1) and per UDP association.
pub struct ShadowsocksTransport {
    server: SocketAddr,
    method: SsMethod,
    psk: Vec<u8>,
    protector: Option<SocketProtector>,
}

impl ShadowsocksTransport {
    /// Build from a validated `(server, method, psk)`. `psk` is the already-decoded key
    /// (`method.key_len()` bytes); the builder in `transport/mod.rs` decodes + length-checks it.
    pub fn new(
        server: SocketAddr,
        method: SsMethod,
        psk: Vec<u8>,
        protector: Option<SocketProtector>,
    ) -> Self {
        ShadowsocksTransport {
            server,
            method,
            psk,
            protector,
        }
    }
}

#[async_trait]
impl Transport for ShadowsocksTransport {
    async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        let conn = protected_tcp_connect(self.server, self.protector.as_ref()).await?;
        let req = encode_request(self.method, &self.psk, &target)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        // The request prefix is buffered in the stream and flushed on first write/flush; the netstack
        // forwarder will issue the first write (or the peer is client-first). Construct and return.
        let stream = ShadowsocksStream::new(conn, self.method, self.psk.clone(), req);
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl UdpTransport for ShadowsocksTransport {
    async fn dial_udp(
        &self,
        target: SocketAddr,
    ) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
        if !self.method.is_aes() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Shadowsocks UDP is supported only for the AES methods in this build (chacha UDP needs XChaCha20)",
            ));
        }
        let socket = protected_udp_socket(self.server, self.protector.as_ref())?;
        let socket = UdpSocket::from_std(socket.into())?;
        socket.connect(self.server).await?;
        let socket = Arc::new(socket);

        let mut session_id = [0u8; 8];
        SystemRandom::new()
            .fill(&mut session_id)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "rng"))?;

        let sink = ShadowsocksUdpSink::new(
            Arc::clone(&socket),
            self.method,
            self.psk.clone(),
            target,
            session_id,
        );
        let source =
            ShadowsocksUdpSource::new(socket, self.method, self.psk.clone(), session_id);
        Ok((Box::new(sink), Box::new(source)))
    }
}
```

> Note: the `dial` flushes the request prefix lazily (buffered in `tx_pending`). If interop (Task 14) shows the server needs the prefix before any app write (it shouldn't — SS is request-first and the prefix carries the address), change `dial` to `conn.write_all(&req.bytes).await?` *before* wrapping and start the stream with an empty `tx_pending`. Decide based on the interop result.

The submodule items used here (`encode_request`, `ShadowsocksStream`, `ShadowsocksUdpSink/Source`, `decode_psk`) must be `pub`/`pub(crate)` from their modules — they already are per Tasks 3-11. `decode_psk` is imported for the builder in Task 13 (re-export it: add `pub(crate) use crypto::decode_psk;` if the builder lives in `transport/mod.rs`).

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p spark-core --features shadowsocks shadowsocks::transport_tests`
Expected: PASS.

- [ ] **Step 5: Clippy the whole feature**

Run: `cargo clippy -p spark-core --features shadowsocks --all-targets -- -D warnings`
Expected: clean. Fix any lints (likely `needless_return`, `Other`-error nits — use `io::Error::other(...)` where the repo prefers it).

- [ ] **Step 6: Commit**

```bash
git add core/src/transport/shadowsocks/mod.rs
git commit -m "feat(shadowsocks): ShadowsocksTransport (Transport + UdpTransport)"
```

---

## Task 13: Wiring — builder, `from_config`, `build_one`, resolver arms

**Files:**
- Modify: `core/src/transport/mod.rs` (builder + precedence + `build_one`)
- Modify: `core/src/config/mod.rs` (`first_unresolved_host`)
- Modify: `core/src/bootstrap/mod.rs` (`resolve_endpoints` optional-SNI refactor)

- [ ] **Step 1: Write the failing test**

In `core/src/transport/mod.rs` tests (gated `#[cfg(all(test, feature = "shadowsocks"))]`):

```rust
    #[test]
    fn from_config_builds_a_shadowsocks_transport() {
        let toml = r#"
[transport.shadowsocks]
server = "1.2.3.4:8388"
method = "2022-blake3-aes-256-gcm"
password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
"#;
        let cfg = crate::config::Config::from_toml_str(toml).unwrap();
        // 44-char base64 = 32 bytes -> matches aes-256. Build must succeed.
        let _ = from_config(&cfg).expect("shadowsocks transport builds");
    }

    #[test]
    fn from_config_rejects_a_bad_length_psk() {
        let toml = r#"
[transport.shadowsocks]
server = "1.2.3.4:8388"
method = "2022-blake3-aes-256-gcm"
password = "c2hvcnQ="
"#; // "short" = 5 bytes, not 32
        let cfg = crate::config::Config::from_toml_str(toml).unwrap();
        assert!(from_config(&cfg).is_err());
    }
```

Also a config-side test in `core/src/config/mod.rs`:

```rust
    #[test]
    fn first_unresolved_host_finds_shadowsocks() {
        let toml = r#"
[transport.shadowsocks]
server = "ss.example.com:8388"
method = "2022-blake3-aes-128-gcm"
password = "MTIzNDU2Nzg5MDEyMzQ1Ng=="
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        assert_eq!(cfg.first_unresolved_host().as_deref(), Some("ss.example.com:8388"));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p spark-core --features shadowsocks from_config_builds_a_shadowsocks && echo done`
Expected: FAIL — `from_config` has no shadowsocks arm; builder missing.

- [ ] **Step 3: Add the builder + precedence + `build_one` arm**

In `core/src/transport/mod.rs`, import the config type and add the builder (mirrors `samizdat_transport`):

```rust
use crate::config::ShadowsocksConfig;

/// Build the Shadowsocks transport (feature `shadowsocks`): decode + length-check the base64 PSK,
/// then a [`shadowsocks::ShadowsocksTransport`] serving both TCP and UDP (UDP errors for the chacha
/// method).
#[cfg(feature = "shadowsocks")]
fn shadowsocks_transport(
    cfg: &ShadowsocksConfig,
    protector: Option<SocketProtector>,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    let server = cfg.server.socket_addr()?;
    let psk = shadowsocks::decode_psk(cfg.method, &cfg.password)
        .map_err(|e| io::Error::other(format!("transport.shadowsocks: {e}")))?;
    let t = Arc::new(shadowsocks::ShadowsocksTransport::new(
        server, cfg.method, psk, protector,
    ));
    Ok((t.clone() as Arc<dyn Transport>, t as Arc<dyn UdpTransport>))
}

/// Without the `shadowsocks` feature, a configured SS transport is a hard error (mirrors anytls).
#[cfg(not(feature = "shadowsocks"))]
fn shadowsocks_transport(
    _cfg: &ShadowsocksConfig,
    _protector: Option<SocketProtector>,
) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)> {
    Err(io::Error::other(
        "transport.shadowsocks is configured but spark was built without the `shadowsocks` feature",
    ))
}
```

Expose `decode_psk` from the module: in `core/src/transport/shadowsocks/mod.rs` add `pub(crate) use crypto::decode_psk;` and re-export the transport: `pub use self::transport_items::*;` is not needed — instead make `ShadowsocksTransport` and `decode_psk` reachable as `shadowsocks::ShadowsocksTransport` / `shadowsocks::decode_psk`. (They are defined in `mod.rs` / re-exported there, so `shadowsocks::X` works.)

In `from_config`, add the precedence arm after the `samizdat` block (no `WirePlan` — SS is not TLS):

```rust
    // Shadowsocks 2022 (ADR 0009) — like AnyTLS/Samizdat, takes precedence over the plain `server`
    // tunnel. Not TLS, so it takes no shaping plan.
    if let Some(ss) = &config.transport.shadowsocks {
        return shadowsocks_transport(ss, protector);
    }
```

In `build_one`, add the arm (it ignores `wire`):

```rust
        ServerSpec::Shadowsocks(cfg) => shadowsocks_transport(cfg, protector.cloned()),
```

- [ ] **Step 4: Add the `first_unresolved_host` arm**

In `core/src/config/mod.rs`, extend `singles` and the pool match:

```rust
        let singles = [
            self.transport.anytls.as_ref().map(|c| &c.server),
            self.transport.samizdat.as_ref().map(|c| &c.server),
            self.transport.shadowsocks.as_ref().map(|c| &c.server),
        ];
        let pool = self.transport.servers.iter().filter_map(|e| match &e.spec {
            ServerSpec::Anytls(c) => Some(&c.server),
            ServerSpec::Samizdat(c) => Some(&c.server),
            ServerSpec::Shadowsocks(c) => Some(&c.server),
            ServerSpec::Tunnel(c) => Some(&c.server),
            ServerSpec::Wasm(_) => None,
        });
```

- [ ] **Step 5: Refactor `resolve_endpoints` for the no-SNI case + add the arm**

In `core/src/bootstrap/mod.rs`, change the entries vector so the SNI slot is optional (SS has no SNI):

```rust
    // (endpoint, optional SNI slot). SS-2022 has no SNI; TLS transports do.
    let mut entries: Vec<(&mut Endpoint, Option<&mut Option<String>>)> = Vec::new();
    if let Some(anytls) = config.transport.anytls.as_mut() {
        entries.push((&mut anytls.server, Some(&mut anytls.sni)));
    }
    if let Some(samizdat) = config.transport.samizdat.as_mut() {
        entries.push((&mut samizdat.server, Some(&mut samizdat.sni)));
    }
    if let Some(ss) = config.transport.shadowsocks.as_mut() {
        entries.push((&mut ss.server, None));
    }
    for entry in config.transport.servers.iter_mut() {
        match &mut entry.spec {
            crate::config::ServerSpec::Anytls(c) => entries.push((&mut c.server, Some(&mut c.sni))),
            crate::config::ServerSpec::Samizdat(c) => entries.push((&mut c.server, Some(&mut c.sni))),
            crate::config::ServerSpec::Shadowsocks(c) => entries.push((&mut c.server, None)),
            crate::config::ServerSpec::Tunnel(c) => entries.push((&mut c.server, Some(&mut c.sni))),
            crate::config::ServerSpec::Wasm(_) => {}
        }
    }
    for (ep, sni) in entries {
        if let Some((host, port)) = ep.unresolved() {
            let host = host.to_owned();
            if let Some(sni) = sni {
                if sni.is_none() {
                    *sni = Some(host.clone());
                }
            }
            let addr = resolver
                .resolve(&host, port)
                .await
                .map_err(|e| io::Error::other(format!("couldn't resolve {host}:{port}: {e}")))?;
            *ep = Endpoint::Ip(addr);
        }
    }
    Ok(())
```

- [ ] **Step 6: Run to verify it passes**

Run: `cargo test -p spark-core --features shadowsocks from_config_builds_a_shadowsocks first_unresolved_host_finds_shadowsocks from_config_rejects_a_bad_length`
Expected: PASS (run the relevant tests; all green).

- [ ] **Step 7: Workspace sweep (with and without the feature)**

```bash
cargo build --all-targets
cargo build -p spark-core --features shadowsocks --all-targets
cargo clippy --all-targets -- -D warnings
cargo clippy -p spark-core --features shadowsocks --all-targets -- -D warnings
cargo fmt --all
```
Expected: all clean. Confirm the base build pulls neither `blake3` nor `aes`:
```bash
cargo tree -p spark-core 2>/dev/null | grep -E "blake3|^aes " && echo "LEAK" || echo "base build clean"
```
Expected: `base build clean`.

- [ ] **Step 8: Commit**

```bash
git add core/src/transport/mod.rs core/src/config/mod.rs core/src/bootstrap/mod.rs
git commit -m "feat(shadowsocks): wire into from_config/build_one/resolver"
```

---

## Task 14: Live interop gate vs `shadowsocks-rust`

Proves the wire format against the authoritative oracle. Gated behind an env var so CI without a server skips it (mirrors the AnyTLS/Samizdat live tests).

**Files:**
- Create: `core/tests/shadowsocks_interop.rs`
- Doc: a runbook snippet in `docs/shadowsocks-design.md` §9 (how to stand up the server)

- [ ] **Step 1: Write the gated integration test**

```rust
//! Live interop with a real shadowsocks-rust server. Skipped unless SPARK_SS_SERVER is set.
//!
//! Stand up a server, e.g.:
//!   PSK=$(openssl rand -base64 32)
//!   ssserver -s 127.0.0.1:8388 -m 2022-blake3-aes-256-gcm -k "$PSK" -U
//! then:
//!   SPARK_SS_SERVER=127.0.0.1:8388 SPARK_SS_METHOD=2022-blake3-aes-256-gcm \
//!   SPARK_SS_PSK="$PSK" cargo test -p spark-core --features shadowsocks --test shadowsocks_interop -- --nocapture
#![cfg(feature = "shadowsocks")]

use std::env;
use std::time::Duration;

use spark_core::config::Config;
use spark_core::transport::from_config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Build a `Config` with `[transport.shadowsocks]` from the env, returning `None` to skip.
fn config_from_env() -> Option<Config> {
    let server = env::var("SPARK_SS_SERVER").ok()?;
    let method = env::var("SPARK_SS_METHOD").unwrap_or_else(|_| "2022-blake3-aes-256-gcm".into());
    let psk = env::var("SPARK_SS_PSK").ok()?;
    let toml = format!(
        "[transport.shadowsocks]\nserver = \"{server}\"\nmethod = \"{method}\"\npassword = \"{psk}\"\n"
    );
    Some(Config::from_toml_str(&toml).expect("valid ss config"))
}

#[tokio::test]
async fn tcp_http_get_through_live_server() {
    let Some(cfg) = config_from_env() else {
        eprintln!("SPARK_SS_SERVER unset; skipping live interop");
        return;
    };
    let (tcp, _udp) = from_config(&cfg).expect("build ss transport");
    // example.com:80 — a stable host that returns an HTTP status line.
    let target = "93.184.215.14:80".parse().unwrap(); // example.com (re-resolve if it changes)
    let mut stream = tcp.dial(target).await.expect("dial through ss");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    stream.flush().await.unwrap();
    let mut head = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut head))
        .await
        .expect("response within 10s")
        .unwrap();
    let line = String::from_utf8_lossy(&head[..n]);
    assert!(line.starts_with("HTTP/1.1 "), "got: {line:?}");
}

#[tokio::test]
async fn udp_dns_through_live_server() {
    let Some(cfg) = config_from_env() else {
        return;
    };
    let (_tcp, udp) = from_config(&cfg).expect("build ss transport");
    let (mut sink, mut source) = udp
        .dial_udp("8.8.8.8:53".parse().unwrap())
        .await
        .expect("dial_udp through ss");
    // Minimal DNS A query for example.com (id 0x1234, RD set).
    let query: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    use spark_core::transport::{PacketSink, PacketSource};
    sink.send(query).await.unwrap();
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(10), source.recv(&mut buf))
        .await
        .expect("dns answer within 10s")
        .unwrap();
    assert!(n > query.len(), "expected a DNS answer, got {n} bytes");
    assert_eq!(&buf[0..2], &query[0..2]); // echoed transaction id
}
```

> Verify the public paths (`spark_core::config::Config`, `spark_core::transport::from_config`, the `PacketSink`/`PacketSource` traits) are exported as written — adjust to the crate's actual `pub use` surface. The `example.com` IP may need re-resolving at test time.

- [ ] **Step 2: Stand up a server and run it for real**

Install `shadowsocks-rust` (`cargo install shadowsocks-rust` or a release binary). Run `ssserver` with `-U` (enable UDP). Export the three env vars and run:

Run: `SPARK_SS_SERVER=... SPARK_SS_METHOD=... SPARK_SS_PSK=... cargo test -p spark-core --features shadowsocks --test shadowsocks_interop -- --nocapture`
Expected: both tests PASS (HTTP 2xx/3xx; a DNS answer). **If they fail, the wire code is wrong — fix `tcp.rs`/`udp.rs` (and the KAT vectors) until the live server accepts them.** This is the gate that makes the rest trustworthy.

- [ ] **Step 3: Capture KAT vectors from the interop run**

While the server is up, capture one known request/response (and one UDP packet) and freeze them as byte-literal KAT tests in `tcp.rs`/`udp.rs` so the format is pinned without needing the live server. Add them as `#[test]` cases; run `cargo test -p spark-core --features shadowsocks` green.

- [ ] **Step 4: Commit**

```bash
git add core/tests/shadowsocks_interop.rs core/src/transport/shadowsocks/
git commit -m "test(shadowsocks): live interop gate vs shadowsocks-rust + frozen KATs"
```

---

## Task 15: ADR 0009 + docs/state sync + final sweep

**Files:**
- Create: `docs/adr/0009-shadowsocks-transport.md`
- Modify: `docs/STATE.md` (record the milestone), `docs/shadowsocks-design.md` (flip Status to Accepted)

- [ ] **Step 1: Write ADR 0009**

Follow the format of `docs/adr/0007-samizdat-transport.md`. Record the decisions: SS-2022 from scratch (no `shadowsocks-rust` dep); RustCrypto `blake3`+`aes` chosen over the CLAUDE.md `aws-lc-rs` fallback (pure-Rust, cmake-free, feature-gated); UDP = AES methods only in v1 (chacha-over-UDP deferred — needs XChaCha20); the `resolve_endpoints` optional-SNI refactor. Status: Accepted (date from the commit, not invented).

- [ ] **Step 2: Update STATE.md and the design Status line**

Add a STATE.md entry noting Shadowsocks shipped (TCP 3 ciphers + UDP AES, live-gated). Flip `docs/shadowsocks-design.md`'s Status from "Proposed — awaiting implementation plan" to "Accepted — implemented in PR #N, live-gated (§9)" once the interop gate passed.

- [ ] **Step 3: Final full sweep + binary size check**

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo clippy -p spark-core --features shadowsocks --all-targets -- -D warnings
cargo test --all-targets
cargo test -p spark-core --features shadowsocks
cargo build --release && ls -la target/release/  # report the stripped binary size (base build, <3 MB gate)
```
Expected: all green; base release binary still under the 3 MB budget (the SS feature is off in the base build).

- [ ] **Step 4: Commit**

```bash
git add docs/adr/0009-shadowsocks-transport.md docs/STATE.md docs/shadowsocks-design.md
git commit -m "docs(shadowsocks): ADR 0009 + state/design sync"
```

---

## Self-Review notes (for the implementer)

- **Spec coverage:** Tasks map to design §: crypto §2/§4 → T3-T4; config §5 → T1; TCP §6 → T6-T8; UDP §7 → T9-T11; transport+wiring §3/§12 → T12-T13; testing §9 → T8/T10/T11/T14; ADR §13 → T15. The chacha-UDP-unsupported behavior (design §1) is asserted in T12.
- **Type consistency:** `Cipher`/`AesBlock`/`NonceCounter`/`session_subkey`/`decode_psk` (crypto.rs); `Request`/`ResponseHead`/`ShadowsocksStream`/`encode_request`/`decode_response_head`/`response_head_len` (tcp.rs); `ReplayWindow`/`build_client_packet`/`parse_server_packet`/`ShadowsocksUdpSink`/`ShadowsocksUdpSource` (udp.rs); `ShadowsocksTransport`/`write_socks_addr`/`read_socks_addr` (mod.rs); `SsMethod`/`ShadowsocksConfig`/`ServerSpec::Shadowsocks` (config). Names are used identically across tasks.
- **No placeholders:** every code step is complete and copy-pasteable. The only deliberately-deferred code is the live interop test's host IP (re-resolve `example.com` at run time) and the public-path verification note in T14 — both are runtime facts, not unwritten logic.
- **Verification-discipline reminders** are embedded at each crate-API boundary (blake3/aes/ring); honor them before writing the impl.
