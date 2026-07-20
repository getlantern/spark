//! BIP324 shared-secret derivation (`v2_ecdh`).

use alloc::vec::Vec;

use crate::crypto::Bip324Crypto;
use crate::{Role, ECDH_SHARED_LEN, ELLSWIFT_LEN};

/// BIP340 tagged-hash tag for the BIP324 ECDH.
const ECDH_TAG: &[u8] = b"bip324_ellswift_xonly_ecdh";

/// Compute the BIP324 shared secret. Takes the raw X-only ECDH x-coordinate from the provider and mixes
/// it into a BIP340 tagged hash together with the two 64-byte ElligatorSwift encodings, in role order
/// (initiator's encoding first). `sha256_tagged(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)`.
/// Consumes `ours_key` (one-shot, matching the host key store).
pub fn v2_ecdh<C: Bip324Crypto>(
    crypto: &mut C,
    ours_key: C::Ephemeral,
    ellswift_ours: &[u8; ELLSWIFT_LEN],
    ellswift_theirs: &[u8; ELLSWIFT_LEN],
    role: Role,
) -> [u8; ECDH_SHARED_LEN] {
    let x = crypto.ellswift_ecdh(ours_key, ellswift_theirs);
    let tag_hash = crypto.sha256(ECDH_TAG);

    let mut msg = Vec::with_capacity(2 * 32 + 2 * ELLSWIFT_LEN + ECDH_SHARED_LEN);
    msg.extend_from_slice(&tag_hash);
    msg.extend_from_slice(&tag_hash);
    // Initiator's ellswift encoding first, then responder's, then the shared x.
    let (first, second) = if role.is_initiator() {
        (ellswift_ours, ellswift_theirs)
    } else {
        (ellswift_theirs, ellswift_ours)
    };
    msg.extend_from_slice(first);
    msg.extend_from_slice(second);
    msg.extend_from_slice(&x);

    crypto.sha256(&msg)
}
