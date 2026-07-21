#![cfg(feature = "native-crypto")]
//! Byte-level wire-compatibility interop against the **rust-bitcoin `bip324` reference crate**. This is
//! the proof that matters for a dynamic transport: our sans-io core (driven by the `NativeCrypto`
//! provider) completes the BIP324 handshake and exchanges packets with the canonical implementation, in
//! both role assignments — so a Lantern egress that speaks our BIP324 is indistinguishable on the wire
//! from a real Bitcoin v2 node.
//!
//! Their side uses the high-level blocking `bip324::io::Protocol` (which runs the whole handshake in its
//! constructor), so it runs on a spawned thread while we drive our side over the other end of a real TCP
//! loopback with the little sync driver below.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use bip324_core::crypto::Bip324Crypto;
use bip324_core::{Handshake, Role, Session};

mod native;
use native::NativeCrypto;

const MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

/// Drive our sans-io handshake to completion over a blocking TCP stream: emit-at-connect, then
/// write-outbound / read-inbound / step until the session materializes.
fn drive_ours(stream: &mut TcpStream, role: Role) -> (NativeCrypto, Session) {
    let mut crypto = NativeCrypto::new();
    let mut hs = Handshake::<NativeCrypto>::new(role, MAGIC, b"").expect("handshake");
    let mut buf = [0u8; 4096];

    let step = hs.step(&mut crypto, &[]).expect("emit-at-connect");
    if !step.outbound.is_empty() {
        stream.write_all(&step.outbound).expect("write opening");
    }
    let mut session = step.session;
    while session.is_none() {
        let n = stream.read(&mut buf).expect("read handshake");
        assert!(n > 0, "peer closed mid-handshake");
        let step = hs.step(&mut crypto, &buf[..n]).expect("handshake step");
        if !step.outbound.is_empty() {
            stream.write_all(&step.outbound).expect("write handshake");
        }
        session = step.session;
    }
    (crypto, session.unwrap())
}

/// One end of the interop: their `bip324::io::Protocol` in `their_role`, reading `expect` and replying
/// `reply`. Runs on its own thread because `Protocol::new` blocks through the whole handshake.
fn spawn_theirs(
    listener: TcpListener,
    their_role: bip324::Role,
    expect: &'static [u8],
    reply: &'static [u8],
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let reader = std::io::BufReader::new(sock.try_clone().expect("clone"));
        let mut proto = bip324::io::Protocol::new(MAGIC, their_role, None, None, reader, sock)
            .expect("their handshake completes against ours");
        let got = proto.read().expect("their read");
        assert_eq!(got.contents(), expect, "reference decrypts our packet");
        proto
            .write(&bip324::io::Payload::genuine(reply.to_vec()))
            .expect("their write");
    })
}

/// Exchange one packet each way and assert both sides recover the plaintext.
fn round_trip(
    stream: &mut TcpStream,
    crypto: &NativeCrypto,
    session: &mut Session,
    send: &[u8],
    expect: &[u8],
) {
    stream
        .write_all(&session.encrypt(crypto, send).expect("encrypt"))
        .expect("send");
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).expect("recv");
    assert!(n > 0, "peer closed before replying");
    let msgs = session.decrypt(crypto, &buf[..n]).expect("decrypt");
    assert_eq!(
        msgs,
        vec![expect.to_vec()],
        "we decrypt the reference's packet"
    );
}

#[test]
fn ours_initiator_interops_with_reference_responder() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let theirs = spawn_theirs(
        listener,
        bip324::Role::Responder,
        b"ping from ours",
        b"pong from ref",
    );

    let mut stream = TcpStream::connect(addr).expect("connect");
    let (crypto, mut session) = drive_ours(&mut stream, Role::Initiator);
    round_trip(
        &mut stream,
        &crypto,
        &mut session,
        b"ping from ours",
        b"pong from ref",
    );
    theirs.join().expect("their thread");
}

#[test]
fn ours_responder_interops_with_reference_initiator() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let theirs = spawn_theirs(
        listener,
        bip324::Role::Initiator,
        b"ping from ours",
        b"pong from ref",
    );

    let mut stream = TcpStream::connect(addr).expect("connect");
    let (crypto, mut session) = drive_ours(&mut stream, Role::Responder);
    round_trip(
        &mut stream,
        &crypto,
        &mut session,
        b"ping from ours",
        b"pong from ref",
    );
    theirs.join().expect("their thread");
}
