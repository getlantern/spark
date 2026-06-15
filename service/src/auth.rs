//! Peer authorization for the control channel.
//!
//! The control socket is a privilege boundary: the service runs privileged, clients run as
//! the logged-in user, so a connecting peer must be authorized — never trusted just for
//! connecting (process-architecture-and-ipc.md §3). On Linux the peer's credentials come
//! from `SO_PEERCRED`; this module is the pure, testable *policy* applied to them. Extracting
//! the credentials from a live `UnixStream` (and resolving supplementary group membership) is
//! the platform glue wired in the privileged/live path.

/// Credentials of a connected peer, as reported by `SO_PEERCRED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCreds {
    /// Effective user id of the peer process.
    pub uid: u32,
    /// Primary group id of the peer process.
    pub gid: u32,
}

/// Who may control the service. The decided desktop policy is **root + the `spark` group**.
#[derive(Debug, Clone, Default)]
pub struct AuthPolicy {
    /// Group id of the `spark` group whose members may control the service.
    pub spark_gid: Option<u32>,
    /// Additional explicitly-allowed uids (e.g. a configured operator). Empty by default.
    pub allow_uids: Vec<u32>,
}

impl AuthPolicy {
    /// A policy allowing root and members of the `spark` group at `spark_gid`.
    pub fn root_and_group(spark_gid: u32) -> Self {
        Self {
            spark_gid: Some(spark_gid),
            allow_uids: Vec::new(),
        }
    }

    /// Whether `creds` may control the service. Root (uid 0) is always allowed; otherwise the
    /// peer must be in the `spark` group or an explicitly-allowed uid.
    ///
    /// Note: `SO_PEERCRED` reports only the peer's *primary* gid. The live path should resolve
    /// the peer uid's full group set and pass a `PeerCreds` whose `gid` reflects `spark`
    /// membership; this policy intentionally stays a pure function of `(uid, gid)`.
    pub fn authorize(&self, creds: &PeerCreds) -> bool {
        creds.uid == 0 || self.spark_gid == Some(creds.gid) || self.allow_uids.contains(&creds.uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPARK_GID: u32 = 4242;

    #[test]
    fn root_is_always_allowed() {
        let policy = AuthPolicy::root_and_group(SPARK_GID);
        assert!(policy.authorize(&PeerCreds { uid: 0, gid: 99 }));
    }

    #[test]
    fn spark_group_member_is_allowed() {
        let policy = AuthPolicy::root_and_group(SPARK_GID);
        assert!(policy.authorize(&PeerCreds {
            uid: 1000,
            gid: SPARK_GID
        }));
    }

    #[test]
    fn other_users_are_denied() {
        let policy = AuthPolicy::root_and_group(SPARK_GID);
        assert!(!policy.authorize(&PeerCreds {
            uid: 1000,
            gid: 1000
        }));
    }

    #[test]
    fn explicit_operator_uid_is_allowed() {
        let policy = AuthPolicy {
            spark_gid: Some(SPARK_GID),
            allow_uids: vec![1000],
        };
        assert!(policy.authorize(&PeerCreds {
            uid: 1000,
            gid: 1000
        }));
    }
}
