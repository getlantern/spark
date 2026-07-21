#![cfg(feature = "native-crypto")]
//! The Lantern side-door MAC: tag generation/verification, and the initiator weaving the tag into its
//! opening garbage such that (a) a Lantern egress sharing `k_srv` can classify the connection and (b) a
//! plain BIP324 responder still completes the handshake (the tag is transparent garbage to it).

use std::mem;

use bip324_core::crypto::Bip324Crypto;
use bip324_core::side_door::{side_door_tag, verify_side_door_tag, SIDE_DOOR_TAG_LEN};
use bip324_core::{Handshake, Role, ELLSWIFT_LEN};

mod native;
use native::NativeCrypto;

const MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

#[test]
fn tag_is_deterministic_and_verifies() {
    let mut c = NativeCrypto::new();
    let (_k, ellswift) = c.ellswift_generate();
    let k_srv = b"a shared per-server side-door secret";

    let tag = side_door_tag(&c, k_srv, &ellswift);
    assert_eq!(tag.len(), SIDE_DOOR_TAG_LEN);
    assert_eq!(
        tag,
        side_door_tag(&c, k_srv, &ellswift),
        "deterministic in (k_srv, ellswift)"
    );

    // The generated tag verifies, and trailing extra garbage after it is tolerated.
    assert!(verify_side_door_tag(&c, k_srv, &ellswift, &tag));
    let mut with_extra = tag.to_vec();
    with_extra.extend_from_slice(b"more garbage after the tag");
    assert!(verify_side_door_tag(&c, k_srv, &ellswift, &with_extra));
}

#[test]
fn verify_rejects_wrong_key_tampered_tag_and_short_input() {
    let mut c = NativeCrypto::new();
    let (_k, ellswift) = c.ellswift_generate();
    let k_srv = b"correct key";
    let tag = side_door_tag(&c, k_srv, &ellswift);

    // Wrong server key → different tag → reject (this is what a real Bitcoin peer looks like).
    assert!(!verify_side_door_tag(&c, b"wrong key", &ellswift, &tag));
    // A single flipped bit → reject.
    let mut bad = tag;
    bad[0] ^= 0x01;
    assert!(!verify_side_door_tag(&c, k_srv, &ellswift, &bad));
    // The tag binds to the ellswift: verifying the same tag against a different ellswift → reject.
    let (_k2, other) = c.ellswift_generate();
    assert!(!verify_side_door_tag(&c, k_srv, &other, &tag));
    // Too few bytes to hold a tag → reject, no panic.
    assert!(!verify_side_door_tag(
        &c,
        k_srv,
        &ellswift,
        &tag[..SIDE_DOOR_TAG_LEN - 1]
    ));
}

#[test]
fn verify_fails_closed_on_empty_key() {
    let mut c = NativeCrypto::new();
    let (_k, ellswift) = c.ellswift_generate();
    // A tag under an empty key is publicly computable from the (public) ellswift, so verification must
    // reject an empty key regardless — a misconfigured egress then fails closed (everyone looks like a
    // real Bitcoin peer) instead of trusting a forgeable tag.
    let forgeable = side_door_tag(&c, b"", &ellswift);
    assert!(!verify_side_door_tag(&c, b"", &ellswift, &forgeable));
}

#[test]
fn initiator_opening_carries_a_verifiable_tag() {
    let k_srv = b"per-server side-door secret";
    let mut ci = NativeCrypto::new();
    let mut hi = Handshake::<NativeCrypto>::new(Role::Initiator, MAGIC, b"tail")
        .unwrap()
        .with_side_door(k_srv);

    // Emit-at-connect: opening = ellswift(64) ‖ tag(32) ‖ configured garbage.
    let opening = hi.step(&mut ci, &[]).unwrap().outbound;
    assert!(opening.len() >= ELLSWIFT_LEN + SIDE_DOOR_TAG_LEN);
    let mut ellswift = [0u8; ELLSWIFT_LEN];
    ellswift.copy_from_slice(&opening[..ELLSWIFT_LEN]);
    let garbage = &opening[ELLSWIFT_LEN..];

    // An egress sharing k_srv recovers the tag from the leading garbage; a wrong key does not.
    let verifier = NativeCrypto::new();
    assert!(verify_side_door_tag(&verifier, k_srv, &ellswift, garbage));
    assert!(!verify_side_door_tag(
        &verifier,
        b"a different key",
        &ellswift,
        garbage
    ));
    // The configured tail follows the tag.
    assert_eq!(&garbage[SIDE_DOOR_TAG_LEN..], b"tail");
}

#[test]
fn empty_key_disables_the_initiator_side_door() {
    let mut ci = NativeCrypto::new();
    let mut hi = Handshake::<NativeCrypto>::new(Role::Initiator, MAGIC, b"plain")
        .unwrap()
        .with_side_door(b"");

    // With an empty key the opening is ellswift(64) ‖ the configured garbage only — no recomputable tag
    // that an observer could use to fingerprint the client.
    let opening = hi.step(&mut ci, &[]).unwrap().outbound;
    assert_eq!(opening.len(), ELLSWIFT_LEN + b"plain".len());
    assert_eq!(&opening[ELLSWIFT_LEN..], b"plain");
}

#[test]
fn side_door_handshake_completes_and_round_trips() {
    let k_srv = b"secret";
    let mut ci = NativeCrypto::new();
    let mut cr = NativeCrypto::new();
    let mut hi = Handshake::<NativeCrypto>::new(Role::Initiator, MAGIC, b"")
        .unwrap()
        .with_side_door(k_srv);
    // The responder needs no side-door key: the tag is just part of the garbage it scans past.
    let mut hr = Handshake::<NativeCrypto>::new(Role::Responder, MAGIC, b"").unwrap();

    let mut to_r = hi.step(&mut ci, &[]).unwrap().outbound;
    let mut to_i = hr.step(&mut cr, &[]).unwrap().outbound;
    let mut si = None;
    let mut sr = None;
    for _ in 0..8 {
        if si.is_none() && !to_i.is_empty() {
            let step = hi.step(&mut ci, &mem::take(&mut to_i)).unwrap();
            to_r.extend_from_slice(&step.outbound);
            si = step.session;
        }
        if sr.is_none() && !to_r.is_empty() {
            let step = hr.step(&mut cr, &mem::take(&mut to_r)).unwrap();
            to_i.extend_from_slice(&step.outbound);
            sr = step.session;
        }
        if si.is_some() && sr.is_some() {
            break;
        }
    }
    let mut si = si.expect("initiator completes despite the tagged garbage");
    let mut sr = sr.expect("responder completes (the tag is transparent garbage to it)");

    let wire = si.encrypt(&ci, b"hello over a side-door tunnel").unwrap();
    assert_eq!(
        sr.decrypt(&cr, &wire).unwrap(),
        vec![b"hello over a side-door tunnel".to_vec()]
    );
}
