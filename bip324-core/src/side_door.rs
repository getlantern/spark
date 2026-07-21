//! Lantern's keyed-garbage **side-door MAC** — a Lantern-specific addition on top of BIP324, not part
//! of the spec. A tunnel client (initiator) prepends `tag = HMAC-SHA256(k_srv, DOMAIN ‖ ellswift)` to
//! its opening garbage. A Lantern egress that shares the per-server secret `k_srv` recomputes the tag
//! from the client's ellswift and matches it against the leading garbage bytes: a match means "Lantern
//! client — run the BIP324 tunnel"; a mismatch (a real Bitcoin peer, whose garbage is random and who
//! lacks `k_srv`) means "proxy to the real node." The tag rides inside BIP324's opening random padding,
//! so a non-participant sees only a well-formed BIP324 handshake.
//!
//! Freshness comes from the client's *ephemeral* ellswift, so no clock is needed: the tag is unique per
//! connection, and a captured `(ellswift, tag)` can't be replayed to complete a handshake (the attacker
//! lacks the client's ephemeral secret), so replaying it confirms nothing to a prober. HMAC is
//! `crypto.hkdf_extract` (HKDF-Extract *is* HMAC-SHA256), so the side-door needs no primitive the BIP324
//! crypto provider doesn't already expose.

use crate::crypto::Bip324Crypto;
use crate::ELLSWIFT_LEN;

/// Length of the side-door tag (a full HMAC-SHA256 output).
pub const SIDE_DOOR_TAG_LEN: usize = 32;

/// Domain separation for the side-door HMAC, so `k_srv` can't collide with any other keyed use.
const DOMAIN: &[u8] = b"lantern/bip324-side-door/v1";
const DOMAIN_LEN: usize = DOMAIN.len();

/// The side-door tag `HMAC-SHA256(k_srv, DOMAIN ‖ ellswift)` for a client's ellswift key.
pub fn side_door_tag<C: Bip324Crypto>(
    crypto: &C,
    k_srv: &[u8],
    ellswift: &[u8; ELLSWIFT_LEN],
) -> [u8; SIDE_DOOR_TAG_LEN] {
    // DOMAIN ‖ ellswift, assembled on the stack (both fixed-size) — no per-tag heap allocation.
    let mut ikm = [0u8; DOMAIN_LEN + ELLSWIFT_LEN];
    ikm[..DOMAIN_LEN].copy_from_slice(DOMAIN);
    ikm[DOMAIN_LEN..].copy_from_slice(ellswift);
    // HKDF-Extract(salt, ikm) == HMAC-SHA256(salt, ikm); key the MAC with the server secret.
    crypto.hkdf_extract(k_srv, &ikm)
}

/// Whether `candidate` (a peer's leading garbage bytes) opens with the tag expected for this `k_srv` +
/// peer `ellswift` — i.e. whether this is a Lantern tunnel client. The tag comparison is constant-time.
pub fn verify_side_door_tag<C: Bip324Crypto>(
    crypto: &C,
    k_srv: &[u8],
    ellswift: &[u8; ELLSWIFT_LEN],
    candidate: &[u8],
) -> bool {
    if candidate.len() < SIDE_DOOR_TAG_LEN {
        return false;
    }
    let expected = side_door_tag(crypto, k_srv, ellswift);
    ct_eq(&expected, &candidate[..SIDE_DOOR_TAG_LEN])
}

/// Constant-time equality for equal-length byte slices — no timing side channel while matching the tag.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
