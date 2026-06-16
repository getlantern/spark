//! Resolving a peer uid's full login group set (its supplementary groups).
//!
//! `SO_PEERCRED` / `getpeereid` report only the peer's *primary* gid, but a human is normally
//! placed in the `spark` group as a **supplementary** group (their primary group stays
//! `staff` / their own). So to honor the "root + `spark` group" policy we resolve the uid's
//! full login group set the same way a fresh login would: `getpwuid_r` (uid → name) then
//! `getgrouplist` (name → groups). Best-effort — on any lookup failure we fall back to just
//! the primary gid, so the policy still works, it simply can't see supplementary membership.

#[cfg(unix)]
use std::ffi::{CStr, CString};

// `getgrouplist`'s group buffer element type differs by platform (Apple: `c_int`,
// Linux/other: `gid_t`); both are 32-bit, so we collect into the right type and cast to `u32`.
#[cfg(all(unix, target_os = "macos"))]
type RawGid = libc::c_int;
#[cfg(all(unix, not(target_os = "macos")))]
type RawGid = libc::gid_t;

/// Resolve the full group set for `uid` (login groups, including supplementary), given its
/// primary `gid`. Always includes `gid`; on any lookup failure returns just `[gid]`.
#[cfg(unix)]
pub fn resolve_groups(uid: u32, gid: u32) -> Vec<u32> {
    match username_of(uid) {
        Some(name) => grouplist(&name, gid),
        None => vec![gid],
    }
}

/// Look up the login name for `uid` via `getpwuid_r` (the reentrant form — the daemon is
/// multi-threaded). Returns `None` if the uid has no passwd entry or the call fails.
#[cfg(unix)]
fn username_of(uid: u32) -> Option<CString> {
    // `_SC_GETPW_R_SIZE_MAX` may be -1 (indeterminate); fall back to 16 KiB.
    let bufsize = match unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) } {
        n if n > 0 => n as usize,
        _ => 16 * 1024,
    };
    let mut buf = vec![0 as libc::c_char; bufsize];
    // SAFETY: `getpwuid_r` fully initializes `pwd` on success; we read it only when it reports
    // success AND `result` is non-null (the documented "found" signal). `pw_name` then points
    // into `buf`, which outlives the `CStr` read below.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: `result` non-null ⇒ `pwd.pw_name` is a valid NUL-terminated string in `buf`.
    Some(unsafe { CStr::from_ptr(pwd.pw_name) }.to_owned())
}

/// Wrap `getgrouplist` for `name` with primary group `gid`. Retries once with the
/// kernel-reported size if the initial buffer is too small; falls back to `[gid]` on failure.
#[cfg(unix)]
fn grouplist(name: &CStr, gid: u32) -> Vec<u32> {
    // Typical accounts belong to a handful of groups; 32 covers the common case in one call.
    let mut capacity: libc::c_int = 32;
    for _ in 0..2 {
        let mut groups = vec![0 as RawGid; capacity.max(1) as usize];
        let mut count = capacity;
        // SAFETY: `name` is a valid C string; `groups` has `count` writable slots; `getgrouplist`
        // writes at most `count` entries and updates `count` with the number written (or, on
        // overflow, the number required).
        let rc = unsafe {
            libc::getgrouplist(
                name.as_ptr(),
                gid as RawGid,
                groups.as_mut_ptr(),
                &mut count,
            )
        };
        if rc >= 0 {
            groups.truncate(count.max(0) as usize);
            return groups.into_iter().map(|g| g as u32).collect();
        }
        // rc < 0: buffer too small; `count` now holds the required size. Grow and retry once.
        if count <= capacity {
            break; // didn't grow (shouldn't happen) — avoid spinning
        }
        capacity = count;
    }
    vec![gid]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_user_groups_include_primary_gid() {
        // Resolving the test process's own uid/gid must at least round-trip the primary gid
        // (the call succeeds for a real, logged-in user and `getgrouplist` always includes it).
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let groups = resolve_groups(uid, gid);
        assert!(
            groups.contains(&gid),
            "resolved groups {groups:?} should contain the primary gid {gid}"
        );
    }

    #[test]
    fn result_always_contains_primary_gid() {
        // The load-bearing invariant: the primary gid is always present, whether the uid
        // resolved (getgrouplist includes the basegid) or not (we fall back to [gid]). We can't
        // portably guarantee a uid has *no* passwd entry — macOS maps -2 to `nobody`, etc. — so
        // we assert the invariant that holds on both paths rather than the fallback exactly.
        let gid = 4242;
        assert!(resolve_groups(31337, gid).contains(&gid));
    }
}
