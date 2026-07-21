//! The BIP324 handshake as a sans-io state machine, both roles. `step` accepts inbound bytes and
//! returns bytes to send plus, on completion, the running [`Session`]. The host driver calls `step(&[])`
//! first (emit-at-connect) then feeds each inbound chunk. All protocol state (ephemeral key, derived
//! keys, buffers) lives in the machine.

use alloc::vec::Vec;
use core::mem;

use crate::crypto::Bip324Crypto;
use crate::ecdh::v2_ecdh;
use crate::packet::{decrypt_length, decrypt_packet, encrypt_packet, Session};
use crate::session::{derive, Keys};
use crate::side_door::side_door_tag;
use crate::{
    Error, Result, Role, AEAD_TAG_LEN, ELLSWIFT_LEN, GARBAGE_TERMINATOR_LEN, HEADER_LEN,
    LENGTH_FIELD_LEN, MAX_GARBAGE_LEN,
};

/// The v1 P2P "version" message command (7 chars + 5 NUL padding). A v2 opening whose bytes 4..16 match
/// this is a v1 (possibly wrong-network) peer — the network-magic-independent v1 tell.
const VERSION_SUFFIX: [u8; 12] = *b"version\x00\x00\x00\x00\x00";

/// The result of one [`Handshake::step`]: bytes to write to the peer, and the [`Session`] once complete.
pub struct HandshakeStep {
    pub outbound: Vec<u8>,
    pub session: Option<Session>,
}

enum State<C: Bip324Crypto> {
    /// Nothing generated yet (before the first `step`).
    New,
    /// Our ephemeral key exists (and, for the initiator, is already on the wire); awaiting the peer's key.
    AwaitPeerKey {
        key: C::Ephemeral,
        ellswift_ours: [u8; ELLSWIFT_LEN],
        sent_garbage: Vec<u8>,
    },
    /// Keys derived; scanning the peer's garbage for its terminator.
    AwaitPeerTerminator {
        keys: Keys,
    },
    /// Terminator found; decrypting packets until the peer's (genuine) version packet.
    AwaitVersion {
        keys: Keys,
        recv_garbage: Vec<u8>,
        pending_len: Option<usize>,
        first_recv: bool,
    },
    Done,
    /// Transient placeholder while a variant is moved out; a re-entrant call in this state is a bug.
    Poisoned,
}

/// The BIP324 handshake driver. Generic over the crypto provider so the same logic runs in the WASM
/// guest (host-fn provider) and natively (RustCrypto/secp256k1 provider).
pub struct Handshake<C: Bip324Crypto> {
    role: Role,
    magic: [u8; 4],
    garbage: Vec<u8>,
    /// Per-server side-door secret. When set, the initiator prepends `HMAC(k_srv, ellswift)` to its
    /// opening garbage so a Lantern egress can distinguish it from a real Bitcoin peer (see
    /// [`side_door`](crate::side_door)). Ignored for the responder.
    side_door_key: Option<Vec<u8>>,
    buf: Vec<u8>,
    state: State<C>,
}

impl<C: Bip324Crypto> Handshake<C> {
    /// Start a handshake for `role` on `network_magic`, sending `garbage` after our public key (the
    /// caller chooses the garbage — random, or carrying a side-door MAC; ≤ [`MAX_GARBAGE_LEN`]).
    pub fn new(role: Role, network_magic: [u8; 4], garbage: &[u8]) -> Result<Self> {
        if garbage.len() > MAX_GARBAGE_LEN {
            return Err(Error::GarbageTooLong);
        }
        Ok(Self {
            role,
            magic: network_magic,
            garbage: garbage.to_vec(),
            side_door_key: None,
            buf: Vec::new(),
            state: State::New,
        })
    }

    /// Enable the Lantern side-door: the initiator prepends `HMAC(k_srv, ellswift)`
    /// ([`SIDE_DOOR_TAG_LEN`](crate::side_door::SIDE_DOOR_TAG_LEN) bytes) to its opening garbage, keyed
    /// by the per-server secret `k_srv`. A no-op for the responder. The tag counts toward
    /// [`MAX_GARBAGE_LEN`]; if `garbage.len() + tag` would exceed it the first `step` errors
    /// [`Error::GarbageTooLong`].
    pub fn with_side_door(mut self, k_srv: &[u8]) -> Self {
        self.side_door_key = Some(k_srv.to_vec());
        self
    }

    /// Advance the handshake: buffer `inbound`, and return bytes to send + the [`Session`] once the
    /// peer's version packet has been authenticated. Call once with `&[]` at connect (emit-at-connect).
    pub fn step(&mut self, crypto: &mut C, inbound: &[u8]) -> Result<HandshakeStep> {
        self.buf.extend_from_slice(inbound);
        let mut outbound = Vec::new();

        let session = loop {
            match mem::replace(&mut self.state, State::Poisoned) {
                State::New => {
                    let (key, ellswift_ours) = crypto.ellswift_generate();
                    let mut sent_garbage = self.garbage.clone();
                    // The initiator opens with its key + garbage; the responder waits for the peer first.
                    if self.role.is_initiator() {
                        // With a side-door key, prepend HMAC(k_srv, ellswift) so a Lantern egress can
                        // classify this as a tunnel client (a real Bitcoin peer's garbage won't match).
                        // It becomes part of the sent garbage — hence of the version-packet AAD — so the
                        // peer authenticates the same bytes it scans past.
                        if let Some(k) = &self.side_door_key {
                            let tag = side_door_tag(crypto, k, &ellswift_ours);
                            if sent_garbage.len() + tag.len() > MAX_GARBAGE_LEN {
                                return Err(Error::GarbageTooLong);
                            }
                            let mut g = Vec::with_capacity(tag.len() + sent_garbage.len());
                            g.extend_from_slice(&tag);
                            g.extend_from_slice(&sent_garbage);
                            sent_garbage = g;
                        }
                        outbound.extend_from_slice(&ellswift_ours);
                        outbound.extend_from_slice(&sent_garbage);
                    }
                    self.state = State::AwaitPeerKey {
                        key,
                        ellswift_ours,
                        sent_garbage,
                    };
                }
                State::AwaitPeerKey {
                    key,
                    ellswift_ours,
                    sent_garbage,
                } => {
                    if self.buf.len() < ELLSWIFT_LEN {
                        self.state = State::AwaitPeerKey {
                            key,
                            ellswift_ours,
                            sent_garbage,
                        };
                        break None;
                    }
                    let mut peer = [0u8; ELLSWIFT_LEN];
                    peer.copy_from_slice(&self.buf[..ELLSWIFT_LEN]);
                    if peer[4..16] == VERSION_SUFFIX {
                        // Remote is a v1 (or wrong-network) peer; state stays Poisoned (terminal).
                        return Err(Error::V1Peer);
                    }
                    self.buf.drain(..ELLSWIFT_LEN);

                    let ecdh_secret = v2_ecdh(crypto, key, &ellswift_ours, &peer, self.role);
                    let mut keys = derive(crypto, &ecdh_secret, &self.magic, self.role);

                    // The responder now puts its key + garbage on the wire (the initiator already did).
                    if !self.role.is_initiator() {
                        outbound.extend_from_slice(&ellswift_ours);
                        outbound.extend_from_slice(&sent_garbage);
                    }
                    // Both sides: garbage terminator, then the version packet with our garbage as AAD.
                    outbound.extend_from_slice(&keys.send_garbage_terminator);
                    let version = encrypt_packet(
                        crypto,
                        &mut keys.send_l,
                        &mut keys.send_p,
                        &[],
                        &sent_garbage,
                        false,
                    )?;
                    outbound.extend_from_slice(&version);
                    self.state = State::AwaitPeerTerminator { keys };
                }
                State::AwaitPeerTerminator { keys } => {
                    match find_terminator(&self.buf, &keys.recv_garbage_terminator)? {
                        Some(pos) => {
                            let recv_garbage = self.buf[..pos].to_vec();
                            self.buf.drain(..pos + GARBAGE_TERMINATOR_LEN);
                            self.state = State::AwaitVersion {
                                keys,
                                recv_garbage,
                                pending_len: None,
                                first_recv: true,
                            };
                        }
                        None => {
                            self.state = State::AwaitPeerTerminator { keys };
                            break None;
                        }
                    }
                }
                State::AwaitVersion {
                    mut keys,
                    recv_garbage,
                    mut pending_len,
                    mut first_recv,
                } => {
                    // Decrypt packets until the first genuine one (the version packet); skip decoys. The
                    // first received packet authenticates the peer's garbage via AAD.
                    let done = loop {
                        match pending_len {
                            None => {
                                if self.buf.len() < LENGTH_FIELD_LEN {
                                    break false;
                                }
                                let mut enc = [0u8; LENGTH_FIELD_LEN];
                                enc.copy_from_slice(&self.buf[..LENGTH_FIELD_LEN]);
                                let len = decrypt_length(crypto, &mut keys.recv_l, &enc);
                                self.buf.drain(..LENGTH_FIELD_LEN);
                                pending_len = Some(len);
                            }
                            Some(len) => {
                                let need = HEADER_LEN + len + AEAD_TAG_LEN;
                                if self.buf.len() < need {
                                    break false;
                                }
                                let aad: &[u8] = if first_recv { &recv_garbage } else { &[] };
                                // Decrypt in place from the buffer; drain only after authentication.
                                let packet = decrypt_packet(
                                    crypto,
                                    &mut keys.recv_p,
                                    &self.buf[..need],
                                    aad,
                                )?;
                                self.buf.drain(..need);
                                first_recv = false;
                                pending_len = None;
                                if !packet.ignore {
                                    break true;
                                }
                            }
                        }
                    };
                    if done {
                        self.state = State::Done;
                        // Any bytes read past the version packet are the peer's first steady-state wire
                        // (coalesced with the handshake over a real stream) — carry them into the
                        // session so the first packet isn't dropped.
                        break Some(Session::new(
                            self.role,
                            keys,
                            core::mem::take(&mut self.buf),
                        ));
                    }
                    self.state = State::AwaitVersion {
                        keys,
                        recv_garbage,
                        pending_len,
                        first_recv,
                    };
                    break None;
                }
                State::Done => {
                    self.state = State::Done;
                    break None;
                }
                State::Poisoned => return Err(Error::WrongState),
            }
        };

        Ok(HandshakeStep { outbound, session })
    }
}

/// Find the first offset at which `term` occurs in `buf` (the boundary between the peer's garbage and
/// its terminator). `Ok(Some(pos))` = found; `Ok(None)` = need more bytes; `Err` = garbage exceeded the
/// maximum without a terminator (protocol violation / attack).
fn find_terminator(buf: &[u8], term: &[u8; GARBAGE_TERMINATOR_LEN]) -> Result<Option<usize>> {
    if buf.len() < GARBAGE_TERMINATOR_LEN {
        return Ok(None);
    }
    let last_start = buf.len() - GARBAGE_TERMINATOR_LEN;
    let max_pos = MAX_GARBAGE_LEN.min(last_start);
    for pos in 0..=max_pos {
        if &buf[pos..pos + GARBAGE_TERMINATOR_LEN] == term {
            return Ok(Some(pos));
        }
    }
    if last_start >= MAX_GARBAGE_LEN {
        // Every valid terminator start (0..=MAX_GARBAGE_LEN) has been searched with no match; a
        // terminator can no longer appear within the allowed garbage window.
        Err(Error::NoGarbageTerminator)
    } else {
        Ok(None)
    }
}
