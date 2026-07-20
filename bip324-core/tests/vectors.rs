//! Byte-exact validation of the BIP324 crypto core against the official BIP324 packet-encoding test
//! vectors (bitcoin/bips `bip-0324/packet_encoding_test_vectors.csv`), via a `NativeCrypto` provider.
//! Each vector fixes the ephemeral keys + role and gives the resulting shared secret, session id,
//! garbage terminators, and the exact ciphertext of the `in_idx`-th packet — so a mismatch anywhere in
//! the tagged-hash ECDH, HKDF key schedule, FSChaCha20 length cipher, or FSChaCha20Poly1305 packet
//! cipher (including its 224-message rekeying, exercised by the high-index vectors) is caught.

use bip324_core::ecdh::v2_ecdh;
use bip324_core::packet::encrypt_packet;
use bip324_core::session::derive;
use bip324_core::{Role, ELLSWIFT_LEN};

mod native;
use native::NativeCrypto;

/// Bitcoin mainnet network magic — the magic the reference vectors are generated with (it enters the
/// HKDF salt, so the derived keys/session-id/terminators depend on it).
const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    let v = unhex(s);
    assert_eq!(v.len(), N, "expected {N} bytes, got {}", v.len());
    v.try_into().unwrap()
}

#[test]
fn packet_encoding_test_vectors() {
    let csv = include_str!("vectors/packet_encoding_test_vectors.csv");
    let mut lines = csv.lines();
    lines.next().expect("header"); // skip header

    let mut checked = 0;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split(',').collect();
        // Columns per the CSV header.
        let in_idx: usize = f[0].parse().unwrap();
        let priv_ours: [u8; 32] = arr(f[1]);
        let ell_ours: [u8; ELLSWIFT_LEN] = arr(f[2]);
        let ell_theirs: [u8; ELLSWIFT_LEN] = arr(f[3]);
        let initiating = f[4] == "1";
        let contents = unhex(f[5]);
        let multiply: usize = f[6].parse().unwrap();
        let aad = unhex(f[7]);
        let ignore = f[8] == "1";
        let exp_shared_secret: [u8; 32] = arr(f[12]);
        let exp_send_gt = unhex(f[17]);
        let exp_recv_gt = unhex(f[18]);
        let exp_session_id: [u8; 32] = arr(f[19]);
        let out_ciphertext = f[20];
        let out_ciphertext_endswith = f[21];

        let role = if initiating {
            Role::Initiator
        } else {
            Role::Responder
        };

        let mut crypto = NativeCrypto::new();

        // 1. Shared secret: raw X-only ECDH mixed into the BIP340 tagged hash.
        let eph = crypto.ephemeral_from_parts(priv_ours, ell_ours);
        let shared = v2_ecdh(&mut crypto, eph, &ell_ours, &ell_theirs, role);
        assert_eq!(shared, exp_shared_secret, "idx {in_idx}: shared secret");

        // 2. Key schedule: session id + garbage terminators (send/recv already role-mapped).
        let mut keys = derive(&crypto, &shared, &MAINNET_MAGIC, role);
        assert_eq!(keys.session_id, exp_session_id, "idx {in_idx}: session id");
        assert_eq!(
            keys.send_garbage_terminator.as_slice(),
            exp_send_gt.as_slice(),
            "idx {in_idx}: send garbage terminator"
        );
        assert_eq!(
            keys.recv_garbage_terminator.as_slice(),
            exp_recv_gt.as_slice(),
            "idx {in_idx}: recv garbage terminator"
        );

        // 3. Packet cipher: advance the send ciphers with `in_idx` empty packets, then encrypt the
        //    target packet and compare its wire bytes byte-for-byte.
        for _ in 0..in_idx {
            encrypt_packet(&crypto, &mut keys.send_l, &mut keys.send_p, &[], &[], false)
                .expect("dummy packet");
        }
        let mut real_contents = Vec::with_capacity(contents.len() * multiply);
        for _ in 0..multiply {
            real_contents.extend_from_slice(&contents);
        }
        let ct = encrypt_packet(
            &crypto,
            &mut keys.send_l,
            &mut keys.send_p,
            &real_contents,
            &aad,
            ignore,
        )
        .expect("target packet");
        let ct_hex: String = ct.iter().map(|b| format!("{b:02x}")).collect();

        if !out_ciphertext.is_empty() {
            assert_eq!(ct_hex, out_ciphertext, "idx {in_idx}: full ciphertext");
        } else {
            assert!(
                ct_hex.ends_with(out_ciphertext_endswith),
                "idx {in_idx}: ciphertext must end with {out_ciphertext_endswith}, got …{}",
                &ct_hex[ct_hex.len().saturating_sub(out_ciphertext_endswith.len())..]
            );
        }
        checked += 1;
    }
    assert!(
        checked >= 7,
        "expected the full vector set, checked {checked}"
    );
}
