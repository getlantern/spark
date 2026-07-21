//! Sans-io BIP324 protocol core (Bitcoin v2 P2P encrypted transport), ADR 0013 §7 step 4.
//!
//! This crate implements the BIP324 handshake + packet framing as pure, no-I/O state machines that are
//! **generic over a [`crypto::Bip324Crypto`] provider**. It performs no network I/O and pulls no crypto
//! crate of its own — the provider supplies every primitive (ellswift keygen/ECDH, SHA-256, HKDF,
//! ChaCha20, ChaCha20-Poly1305, RNG). That keeps it `#![no_std]` and lets the same logic run:
//!
//! * in the WASM dynamic-transport guest, with the provider forwarding to the `env` host functions
//!   (`core/src/transport/wasm/mod.rs`) — the crypto lives in the sandbox host, not the module; and
//! * in native tests / a native fallback engine, with a RustCrypto + secp256k1 provider.
//!
//! The spec (`docs/bitcoin-transport-design.md`, BIP324 itself) and the intricate rekeying ciphers
//! demand byte-exact interop, so the crate is validated against the official BIP324 packet-encoding
//! vectors and the rust-bitcoin `bip324` reference (see `tests/`).
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use core::fmt;

pub mod crypto;
pub mod ecdh;
pub mod handshake;
pub mod packet;
pub mod session;
pub mod side_door;

pub use crypto::Bip324Crypto;
pub use handshake::{Handshake, HandshakeStep};
pub use packet::Session;
pub use side_door::{
    side_door_tag, side_door_tag_with, verify_side_door_tag, verify_side_door_tag_with,
    SIDE_DOOR_TAG_LEN,
};

/// Which side of the connection we are. The initiator dials; the responder accepts. The role fixes the
/// ellswift ordering in the ECDH tagged hash and the send/recv assignment of the derived key pairs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

impl Role {
    fn is_initiator(self) -> bool {
        matches!(self, Role::Initiator)
    }
}

/// Length of an ElligatorSwift-encoded public key (32-byte `u` + 32-byte `t`).
pub const ELLSWIFT_LEN: usize = 64;
/// Length of the raw X-only ECDH shared coordinate.
pub const ECDH_SHARED_LEN: usize = 32;
/// Length of a garbage terminator.
pub const GARBAGE_TERMINATOR_LEN: usize = 16;
/// Maximum garbage a peer may send before its terminator.
pub const MAX_GARBAGE_LEN: usize = 4095;
/// Re-key both ciphers after this many packets / length chunks (forward secrecy).
pub const REKEY_INTERVAL: u64 = 224;
/// Bytes of encrypted length prefix per packet.
pub const LENGTH_FIELD_LEN: usize = 3;
/// Bytes of plaintext header per packet (only the ignore bit is defined).
pub const HEADER_LEN: usize = 1;
/// ChaCha20-Poly1305 tag length.
pub const AEAD_TAG_LEN: usize = 16;
/// Header bit that marks a packet as a decoy (to be ignored after authentication).
pub const IGNORE_BIT: u8 = 0x80;
/// Maximum contents length a single packet may carry (`2^24 - 1`).
pub const MAX_CONTENTS_LEN: usize = (1 << 24) - 1;

/// Errors from the BIP324 handshake or packet layer. Any error is terminal for the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A peer's garbage exceeded [`MAX_GARBAGE_LEN`] without a terminator (protocol violation / attack).
    NoGarbageTerminator,
    /// The remote looks like a v1 (or wrong-network) peer: its first 16 bytes matched the v1 prefix.
    V1Peer,
    /// AEAD authentication failed (a tampered or corrupt packet).
    Decrypt,
    /// A packet declared contents longer than [`MAX_CONTENTS_LEN`].
    ContentsTooLong,
    /// Garbage passed to the handshake exceeded [`MAX_GARBAGE_LEN`].
    GarbageTooLong,
    /// A handshake method was called out of sequence for the current state.
    WrongState,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Error::NoGarbageTerminator => "no garbage terminator within the maximum garbage length",
            Error::V1Peer => "remote peer is using the v1 protocol (or a different network)",
            Error::Decrypt => "packet authentication failed",
            Error::ContentsTooLong => "packet contents exceed the maximum length",
            Error::GarbageTooLong => "garbage exceeds the maximum length",
            Error::WrongState => "handshake method called out of sequence",
        };
        f.write_str(s)
    }
}

/// Result alias for the crate.
pub type Result<T> = core::result::Result<T, Error>;
