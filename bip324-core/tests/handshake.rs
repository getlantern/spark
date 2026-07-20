//! End-to-end validation of the handshake state machine + steady-state framing by running a
//! `bip324-core` initiator against a `bip324-core` responder over in-memory buffers (both roles), then
//! exchanging packets. This exercises what the vector KAT does not: message sequencing, the
//! garbage/terminator scan, the version packet, role assignment, decoys, and a rekey boundary.

use std::mem;

use bip324_core::{Handshake, Role, Session};

mod native;
use native::NativeCrypto;

const MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

/// Run both handshakes to completion, shuttling bytes between them, and return the two sessions.
fn complete(garbage_i: &[u8], garbage_r: &[u8]) -> (NativeCrypto, Session, NativeCrypto, Session) {
    let mut ci = NativeCrypto::new();
    let mut cr = NativeCrypto::new();
    let mut hi = Handshake::<NativeCrypto>::new(Role::Initiator, MAGIC, garbage_i).unwrap();
    let mut hr = Handshake::<NativeCrypto>::new(Role::Responder, MAGIC, garbage_r).unwrap();

    // Emit-at-connect: the initiator opens with its key + garbage; the responder emits nothing yet.
    let mut to_r = hi.step(&mut ci, &[]).unwrap().outbound;
    let mut to_i = hr.step(&mut cr, &[]).unwrap().outbound;
    let mut si: Option<Session> = None;
    let mut sr: Option<Session> = None;

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

    let si = si.expect("initiator completed");
    let sr = sr.expect("responder completed");
    // No bytes should be left stranded once both complete.
    assert!(
        to_i.is_empty() && to_r.is_empty(),
        "leftover handshake bytes"
    );
    (ci, si, cr, sr)
}

#[test]
fn handshake_derives_a_shared_session() {
    for (gi, gr) in [
        (&b""[..], &b""[..]),
        (&b"initiator garbage"[..], &b"responder garbage!!"[..]),
    ] {
        let (ci, mut si, cr, mut sr) = complete(gi, gr);
        assert_eq!(si.session_id(), sr.session_id(), "session ids must match");
        assert_eq!(si.role(), Role::Initiator);
        assert_eq!(sr.role(), Role::Responder);

        // App messages round-trip both directions.
        let wire = si.encrypt(&ci, b"ping from initiator").unwrap();
        assert_eq!(
            sr.decrypt(&cr, &wire).unwrap(),
            vec![b"ping from initiator".to_vec()]
        );
        let wire = sr.encrypt(&cr, b"pong from responder").unwrap();
        assert_eq!(
            si.decrypt(&ci, &wire).unwrap(),
            vec![b"pong from responder".to_vec()]
        );

        // A decoy packet is authenticated but dropped (surfaces no message).
        let decoy = si.encrypt_decoy(&ci, b"noise").unwrap();
        assert!(sr.decrypt(&cr, &decoy).unwrap().is_empty(), "decoy dropped");
    }
}

#[test]
fn packets_survive_a_rekey_boundary_and_fragmentation() {
    let (ci, mut si, cr, mut sr) = complete(b"", b"");

    // Send well past the 224-message rekey interval; every message must decrypt in order.
    let total = 500usize;
    let mut wire = Vec::new();
    for i in 0..total {
        let msg = format!("message #{i}");
        wire.extend_from_slice(&si.encrypt(&ci, msg.as_bytes()).unwrap());
    }
    // Feed the whole stream in awkward 7-byte fragments to exercise the streaming decryptor.
    let mut received: Vec<Vec<u8>> = Vec::new();
    for chunk in wire.chunks(7) {
        received.extend(sr.decrypt(&cr, chunk).unwrap());
    }
    assert_eq!(received.len(), total, "all messages recovered");
    for (i, msg) in received.iter().enumerate() {
        assert_eq!(msg, format!("message #{i}").as_bytes());
    }

    // The reverse direction still works after the forward burst (independent ciphers).
    let wire = sr.encrypt(&cr, b"final").unwrap();
    assert_eq!(si.decrypt(&ci, &wire).unwrap(), vec![b"final".to_vec()]);
}
