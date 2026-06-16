//! Windows control transport: a named pipe restricted to SYSTEM + Administrators.
//!
//! Windows has no `SO_PEERCRED`; the privilege boundary is the pipe's **DACL**. We create the
//! pipe with a security descriptor granting full control only to Local System (`SY`) and the
//! built-in Administrators group (`BA`), so an unprivileged process cannot open it at all — the
//! OS refuses the connect. That is the Windows analog of the unix peer-cred check
//! (process-architecture-and-ipc.md §3), so there is no per-connection credential test here.
//! The per-connection serve loop ([`crate::conn::serve_connection`]) is shared with unix.
//!
//! NB: built and type-checked against the Windows target, but not yet exercised on a real
//! Windows host — gated with the other privileged live gates.

use std::ffi::{c_void, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::mpsc;
use tracing::debug;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

use crate::conn::serve_connection;
use crate::service::Envelope;

/// SDDL granting `GENERIC_ALL` to Local System (`SY`) and Built-in Administrators (`BA`) only;
/// the DACL is protected (`P`) so no inherited ACEs widen it.
const ADMIN_ONLY_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";
/// `SDDL_REVISION_1` — the only defined SDDL revision.
const SDDL_REVISION_1: u32 = 1;

/// Owns a security descriptor built from [`ADMIN_ONLY_SDDL`] and frees it on drop, and holds the
/// `SECURITY_ATTRIBUTES` that point at it for `create_with_security_attributes_raw`.
struct AdminOnlySecurity {
    descriptor: PSECURITY_DESCRIPTOR,
    attributes: SECURITY_ATTRIBUTES,
}

impl AdminOnlySecurity {
    fn new() -> io::Result<Self> {
        let sddl: Vec<u16> = OsStr::new(ADMIN_ONLY_SDDL)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `sddl` is a NUL-terminated wide string; on success the call allocates a
        // security descriptor we own and must release with `LocalFree`.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0, // FALSE — child processes don't inherit the pipe handle
        };
        Ok(Self {
            descriptor,
            attributes,
        })
    }

    /// Pointer to the `SECURITY_ATTRIBUTES` for `create_with_security_attributes_raw`. Valid as
    /// long as `self` is alive and not moved.
    fn as_ptr(&self) -> *mut c_void {
        &self.attributes as *const SECURITY_ATTRIBUTES as *mut c_void
    }
}

impl Drop for AdminOnlySecurity {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            // SAFETY: `descriptor` came from ConvertStringSecurityDescriptorToSecurityDescriptorW,
            // which documents `LocalFree` as the matching deallocation.
            unsafe { LocalFree(self.descriptor as _) };
        }
    }
}

/// Create one pipe-server instance for `name` with the admin-only DACL. `first` claims the pipe
/// name (set only on the first instance).
fn make_instance(
    name: &OsStr,
    first: bool,
    security: &AdminOnlySecurity,
) -> io::Result<NamedPipeServer> {
    // SAFETY: `as_ptr` points at a live `SECURITY_ATTRIBUTES` whose descriptor is valid for the
    // duration of the call.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .create_with_security_attributes_raw(name, security.as_ptr())
    }
}

/// Accept and serve control connections on the named pipe `name` forever. The DACL is the
/// authorization gate (only SYSTEM/Administrators can open the pipe), so unauthorized peers
/// can't connect in the first place — there is no per-connection credential check.
pub async fn serve(name: &OsStr, commands: mpsc::Sender<Envelope>) -> io::Result<()> {
    let security = AdminOnlySecurity::new()?;
    // Pre-create the first instance; after each client connects, immediately create the next so
    // a new client can connect while the current one is served (the tokio named-pipe idiom —
    // otherwise the next client races into ERROR_PIPE_BUSY).
    let mut server = make_instance(name, true, &security)?;
    loop {
        server.connect().await?;
        let connected = server;
        server = make_instance(name, false, &security)?;

        let commands = commands.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_connection(connected, commands).await {
                debug!(error = %e, "control connection ended with error");
            }
        });
    }
}
