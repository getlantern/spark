//! The unix-socket control listener: accept connections, authenticate the peer, serve.
//!
//! This is the live transport that `serve_connection` ([`crate::conn`]) plugs into. The peer
//! credentials come from the OS (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED`/`getpeereid` on
//! macOS/BSD — both surfaced by tokio's `UnixStream::peer_cred`), so the same
//! [`AuthPolicy`](crate::auth::AuthPolicy) works on every desktop. Binding the socket and
//! running this loop needs the privilege the service holds; the round-trip itself is testable
//! as the current user (a same-uid unix socket needs no root).

use std::io;

use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::auth::{AuthPolicy, PeerCreds};
use crate::conn::serve_connection;
use crate::service::Envelope;

/// Accept and serve control connections forever, authorizing each peer against `policy`.
/// Unauthorized peers are refused (the connection is closed before any message is served).
pub async fn serve(
    listener: UnixListener,
    policy: AuthPolicy,
    commands: mpsc::Sender<Envelope>,
) -> io::Result<()> {
    loop {
        let (stream, _addr) = listener.accept().await?;
        let creds = match stream.peer_cred() {
            Ok(ucred) => {
                let (uid, gid) = (ucred.uid(), ucred.gid());
                // Resolve the peer's full login group set so `spark` membership counts even
                // when it's a supplementary (not primary) group.
                PeerCreds {
                    uid,
                    gid,
                    groups: crate::groups::resolve_groups(uid, gid),
                }
            }
            Err(e) => {
                warn!(error = %e, "could not read peer credentials; refusing connection");
                continue;
            }
        };
        if !policy.authorize(&creds) {
            warn!(
                uid = creds.uid,
                gid = creds.gid,
                "unauthorized control connection refused"
            );
            continue; // dropping `stream` closes it
        }
        debug!(
            uid = creds.uid,
            gid = creds.gid,
            "control connection accepted"
        );

        let commands = commands.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_connection(stream, commands).await {
                debug!(error = %e, "control connection ended with error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::test_support::FakeEngine;
    use crate::service::{channel, run_service};
    use spark_ipc::{Client, RequestPayload, ResponsePayload, TunnelState, PROTOCOL_VERSION};
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;
    use tokio::net::UnixStream;

    fn temp_socket(tag: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("spark-test-{}-{tag}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path); // clear any stale socket
        path
    }

    /// An authorized client completes the handshake and drives connect/status over a real
    /// (same-uid) unix socket — the live transport + `peer_cred` auth, no root needed.
    #[tokio::test]
    async fn authorized_client_drives_the_service() {
        let path = temp_socket("ok");
        let listener = UnixListener::bind(&path).unwrap();

        let (cmd_tx, cmd_rx) = channel();
        let engine = FakeEngine::default();
        let running = engine.running.clone();
        tokio::spawn(run_service(engine, cmd_rx, false));

        // Allow the current user (the test process is the peer).
        let uid = unsafe { libc::getuid() };
        let policy = AuthPolicy {
            spark_gid: None,
            allow_uids: vec![uid],
        };
        tokio::spawn(serve(listener, policy, cmd_tx));

        let mut client = Client::new(UnixStream::connect(&path).await.unwrap());
        assert_eq!(client.handshake().await.unwrap(), PROTOCOL_VERSION);
        assert!(matches!(
            client.request(RequestPayload::Connect).await.unwrap(),
            ResponsePayload::Ack
        ));
        assert!(running.load(Ordering::SeqCst), "engine should be started");
        match client.request(RequestPayload::GetStatus).await.unwrap() {
            ResponsePayload::Status(s) => assert_eq!(s.state, TunnelState::Connected),
            other => panic!("unexpected status reply: {other:?}"),
        }

        let _ = std::fs::remove_file(&path);
    }

    /// A peer not matching the policy is refused: the connection is closed, so the client's
    /// handshake fails. (Skipped if the test runs as root, which the policy always allows.)
    #[tokio::test]
    async fn unauthorized_client_is_refused() {
        if unsafe { libc::getuid() } == 0 {
            return; // root is always authorized; this test is meaningful only as non-root
        }
        let path = temp_socket("denied");
        let listener = UnixListener::bind(&path).unwrap();

        let (cmd_tx, cmd_rx) = channel();
        tokio::spawn(run_service(FakeEngine::default(), cmd_rx, false));

        // Allow only an impossible group; the current non-root user is refused.
        let policy = AuthPolicy {
            spark_gid: Some(u32::MAX),
            allow_uids: vec![],
        };
        tokio::spawn(serve(listener, policy, cmd_tx));

        let mut client = Client::new(UnixStream::connect(&path).await.unwrap());
        assert!(
            client.handshake().await.is_err(),
            "refused connection should fail the handshake"
        );

        let _ = std::fs::remove_file(&path);
    }
}
