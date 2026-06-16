//! Peer authorization for the control channel.
//!
//! The control socket is a privilege boundary: the service runs privileged, clients run as
//! the logged-in user, so a connecting peer must be authorized — never trusted just for
//! connecting (process-architecture-and-ipc.md §3). On Linux the peer's credentials come
//! from `SO_PEERCRED`; this module is the pure, testable *policy* applied to them. Extracting
//! the credentials from a live `UnixStream` (and resolving supplementary group membership) is
//! the platform glue wired in the privileged/live path.

/// Credentials of a connected peer: its `SO_PEERCRED` uid/primary-gid plus the resolved
/// supplementary group set (see [`crate::groups`]). `groups` always contains `gid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCreds {
    /// Effective user id of the peer process.
    pub uid: u32,
    /// Primary group id of the peer process.
    pub gid: u32,
    /// The peer's full login group set (primary + supplementary), resolved from `uid`. Empty
    /// only when resolution was skipped (e.g. in a unit test that sets `gid` directly).
    pub groups: Vec<u32>,
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
    /// peer must be in the `spark` group (as its primary *or* a supplementary group) or be an
    /// explicitly-allowed uid.
    ///
    /// The supplementary set is resolved off the live socket by [`crate::groups`] and arrives
    /// in `creds.groups`; this policy stays a pure function of the credentials it's handed.
    pub fn authorize(&self, creds: &PeerCreds) -> bool {
        if creds.uid == 0 || self.allow_uids.contains(&creds.uid) {
            return true;
        }
        match self.spark_gid {
            Some(gid) => creds.gid == gid || creds.groups.contains(&gid),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPARK_GID: u32 = 4242;

    /// A peer whose primary gid is `gid` and supplementary set is `groups`.
    fn creds(uid: u32, gid: u32, groups: &[u32]) -> PeerCreds {
        PeerCreds {
            uid,
            gid,
            groups: groups.to_vec(),
        }
    }

    #[test]
    fn root_is_always_allowed() {
        let policy = AuthPolicy::root_and_group(SPARK_GID);
        assert!(policy.authorize(&creds(0, 99, &[99])));
    }

    #[test]
    fn spark_group_as_primary_is_allowed() {
        let policy = AuthPolicy::root_and_group(SPARK_GID);
        assert!(policy.authorize(&creds(1000, SPARK_GID, &[SPARK_GID])));
    }

    #[test]
    fn spark_group_as_supplementary_is_allowed() {
        // The common case: primary group is the user's own; `spark` is supplementary.
        let policy = AuthPolicy::root_and_group(SPARK_GID);
        assert!(policy.authorize(&creds(1000, 1000, &[1000, SPARK_GID])));
    }

    #[test]
    fn other_users_are_denied() {
        let policy = AuthPolicy::root_and_group(SPARK_GID);
        assert!(!policy.authorize(&creds(1000, 1000, &[1000, 20])));
    }

    #[test]
    fn explicit_operator_uid_is_allowed() {
        let policy = AuthPolicy {
            spark_gid: Some(SPARK_GID),
            allow_uids: vec![1000],
        };
        assert!(policy.authorize(&creds(1000, 1000, &[1000])));
    }
}
