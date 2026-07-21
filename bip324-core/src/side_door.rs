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

/// The side-door tag `HMAC-SHA256(k_srv, DOMAIN ‖ ellswift)`, computed with a caller-supplied
/// `hmac_sha256(key, msg)` primitive. For callers that have HMAC-SHA256 but not a full
/// [`Bip324Crypto`] — e.g. the egress splitter, which has `ring` — so the canonical MAC input
/// (the domain separation, the field ordering) stays defined here in exactly one place.
pub fn side_door_tag_with<F>(
    hmac_sha256: F,
    k_srv: &[u8],
    ellswift: &[u8; ELLSWIFT_LEN],
) -> [u8; SIDE_DOOR_TAG_LEN]
where
    F: FnOnce(&[u8], &[u8]) -> [u8; SIDE_DOOR_TAG_LEN],
{
    // DOMAIN ‖ ellswift, assembled on the stack (both fixed-size) — no per-tag heap allocation.
    let mut ikm = [0u8; DOMAIN_LEN + ELLSWIFT_LEN];
    ikm[..DOMAIN_LEN].copy_from_slice(DOMAIN);
    ikm[DOMAIN_LEN..].copy_from_slice(ellswift);
    hmac_sha256(k_srv, &ikm)
}

/// The side-door tag `HMAC-SHA256(k_srv, DOMAIN ‖ ellswift)` for a client's ellswift key, using the
/// provider's HMAC (HKDF-Extract *is* HMAC-SHA256). See [`side_door_tag_with`] for callers without a
/// full [`Bip324Crypto`].
pub fn side_door_tag<C: Bip324Crypto>(
    crypto: &C,
    k_srv: &[u8],
    ellswift: &[u8; ELLSWIFT_LEN],
) -> [u8; SIDE_DOOR_TAG_LEN] {
    side_door_tag_with(|salt, ikm| crypto.hkdf_extract(salt, ikm), k_srv, ellswift)
}

/// Whether `candidate` opens with the expected tag, computed with a caller-supplied `hmac_sha256`
/// primitive (see [`side_door_tag_with`]). The tag comparison is constant-time.
pub fn verify_side_door_tag_with<F>(
    hmac_sha256: F,
    k_srv: &[u8],
    ellswift: &[u8; ELLSWIFT_LEN],
    candidate: &[u8],
) -> bool
where
    F: FnOnce(&[u8], &[u8]) -> [u8; SIDE_DOOR_TAG_LEN],
{
    // An empty k_srv makes the tag publicly computable from the (public) ellswift — anyone could forge a
    // match and unmask the egress. Fail closed on that misconfiguration rather than trust the tag.
    if k_srv.is_empty() || candidate.len() < SIDE_DOOR_TAG_LEN {
        return false;
    }
    let expected = side_door_tag_with(hmac_sha256, k_srv, ellswift);
    ct_eq(&expected, &candidate[..SIDE_DOOR_TAG_LEN])
}

/// Whether `candidate` (a peer's leading garbage bytes) opens with the tag expected for this `k_srv` +
/// peer `ellswift` — i.e. whether this is a Lantern tunnel client. The tag comparison is constant-time.
pub fn verify_side_door_tag<C: Bip324Crypto>(
    crypto: &C,
    k_srv: &[u8],
    ellswift: &[u8; ELLSWIFT_LEN],
    candidate: &[u8],
) -> bool {
    verify_side_door_tag_with(
        |salt, ikm| crypto.hkdf_extract(salt, ikm),
        k_srv,
        ellswift,
        candidate,
    )
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
