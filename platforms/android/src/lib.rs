//! `spark-android` — the JNI library (`libspark_android.so`) the Android `VpnService` loads via
//! `System.loadLibrary("spark_android")`.
//!
//! The `VpnService` establishes the tunnel, configures routing, and excludes the app's own sockets
//! (`addDisallowedApplication`), then hands the TUN fd here to run the data path; stop is signalled
//! from `onDestroy`. The run/config/stop logic lives in [`spark_core::fd_tunnel`] — the shim calls the
//! same shared [`run_fd_dispatch`](spark_core::fd_tunnel::run_fd_dispatch) as the Apple C-ABI shim, so
//! the direct / relay / full-config / `lantern-api` self-fetch policy lives in core, once. The shim now
//! carries a config string + data-dir path across JNI (not just `fd`/`mtu` ints), so it uses the `jni`
//! crate for the string marshalling — Android-target-only, so desktop/Apple builds are unaffected.
//!
//! On non-Android targets these symbols are `cfg`-d out, so the crate builds as an empty cdylib
//! and stays in the workspace's green-checked set without affecting desktop builds.

// Kotlin side (package org.getlantern.spark):
//   object SparkBridge {
//       init { System.loadLibrary("spark_android") }
//       // addr = the tun IPv4 packed big-endian into an Int (e.g. 10.0.0.2 -> 0x0A000002); it must
//       // equal VpnService.Builder.addAddress(addr, prefix), and `prefix` must cover addr+1 (the
//       // system stack's synthetic gateway). systemStack: 1 = the kernel-TCP "system" stack, 0 = the
//       // userspace (smoltcp) stack. config/dataDir carry the data-path choice: a null/empty config
//       // (or "lantern-api") self-fetches the pool from the Lantern config-new API into dataDir (the
//       // app files dir); a "host:port" is a plain relay; any other string is a full config.
//       external fun nativeRun(fd: Int, mtu: Int, addr: Int, prefix: Int, systemStack: Int,
//                              config: String?, dataDir: String?): Int
//       external fun nativeStop()
//   }
#[cfg(target_os = "android")]
mod jni {
    use std::path::PathBuf;

    use jni::objects::{JClass, JString};
    use jni::sys::jint;
    use jni::JNIEnv;

    /// `SparkBridge.nativeRun(fd, mtu, addr, prefix, systemStack, config, dataDir)` — adopt the
    /// `VpnService` TUN `fd` (ownership transferred) and run the tunnel, blocking the calling thread
    /// until [`nativeStop`] (or the data path exits). Returns 0 on a clean stop, -1 on error.
    ///
    /// `addr` is the tun IPv4 packed big-endian into a `jint`; the system stack binds its kernel
    /// listener there and derives its gateway as `addr + 1` (so `prefix` must include it). `config`
    /// and `dataDir` carry the controlling app's data-path choice into the shared dispatch
    /// ([`spark_core::fd_tunnel::run_fd_dispatch`], the same one the Apple shim calls): a null/empty
    /// `config` — or the `"lantern-api"` sentinel — self-fetches the pool from the Lantern config-new
    /// API, caching into `dataDir` (the app files dir); a `host:port` is a plain relay; any other
    /// string is a full config. The platform `tun_base` (addr/prefix/system stack) always owns the
    /// tun/stack — Android's `VpnService` already established the interface.
    #[no_mangle]
    pub extern "system" fn Java_org_getlantern_spark_SparkBridge_nativeRun<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        fd: jint,
        mtu: jint,
        addr: jint,
        prefix: jint,
        system_stack: jint,
        config: JString<'local>,
        data_dir: JString<'local>,
    ) -> jint {
        crate::logcat::init();
        // `config` is fail-closed: a non-null string that won't decode is a caller error (an explicit
        // config was provided but is garbage), so close the transferred fd and bail rather than
        // silently collapsing it to "no config" — which would wrongly self-fetch. Mirrors the Apple
        // shim's invalid-UTF-8 handling. A null reference (Kotlin `null`) is a legitimate "no config".
        let cfg = match read_jstring(&mut env, &config) {
            Ok(c) => c,
            Err(()) => {
                spark_core::fd_tunnel::abandon_fd(fd);
                return -1;
            }
        };
        // `data_dir` is lenient: a null/undecodable path → None (self-fetch then fails closed in the
        // dispatch for want of a cache dir). Reject empty (an empty path would cache into the cwd).
        let dir = read_jstring(&mut env, &data_dir)
            .ok()
            .flatten()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        // The platform owns the interface reality: the VpnService addr/prefix + Android's kernel
        // (system) stack. The shared dispatch decides direct / relay / full-config / self-fetch.
        let tun_base = spark_core::fd_tunnel::fd_config(
            std::net::Ipv4Addr::from(addr as u32),
            prefix as u8,
            system_stack != 0,
        );
        spark_core::fd_tunnel::run_fd_dispatch(
            fd,
            mtu as u16,
            cfg.as_deref(),
            dir.as_deref(),
            tun_base,
        )
    }

    /// `SparkBridge.nativeStop()` — signal the running tunnel to stop (from `onDestroy`).
    #[no_mangle]
    pub extern "system" fn Java_org_getlantern_spark_SparkBridge_nativeStop<'local>(
        _env: JNIEnv<'local>,
        _class: JClass<'local>,
    ) {
        spark_core::fd_tunnel::stop();
    }

    /// Read a JNI string into three outcomes: a null reference (Kotlin `null`) → `Ok(None)`; a
    /// readable string → `Ok(Some(s))`; a present-but-undecodable string → `Err(())`. The null guard
    /// is required because `get_string` does not accept a null reference. On a decode failure any
    /// pending Java exception is cleared first — returning into Java (or making further JNI calls)
    /// with an exception pending is undefined. The caller decides whether `Err` is fatal (`config`,
    /// fail-closed) or tolerable (`data_dir`, → `None`).
    fn read_jstring(env: &mut JNIEnv, s: &JString) -> Result<Option<String>, ()> {
        if s.as_raw().is_null() {
            return Ok(None);
        }
        match env.get_string(s) {
            Ok(js) => Ok(Some(js.into())),
            Err(_) => {
                let _ = env.exception_clear();
                Err(())
            }
        }
    }
}

/// Routes the core's `tracing` events to Android logcat (tag `spark`) — without this an Android
/// app's stdout/stderr is discarded, so the core would log nowhere. Uses the NDK's liblog.
#[cfg(target_os = "android")]
mod logcat {
    use std::ffi::{c_char, CString};
    use std::io;
    use std::sync::Once;

    use tracing::Level;

    /// `ANDROID_LOG_INFO` from `<android/log.h>`.
    const ANDROID_LOG_INFO: i32 = 4;
    /// NUL-terminated logcat tag.
    const TAG: &[u8] = b"spark\0";

    #[link(name = "log")]
    extern "C" {
        fn __android_log_write(prio: i32, tag: *const c_char, text: *const c_char) -> i32;
    }

    /// A `tracing_subscriber::fmt` writer that emits each formatted line to logcat.
    struct Writer;
    impl io::Write for Writer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let msg = String::from_utf8_lossy(buf);
            let line = msg.trim_end();
            if !line.is_empty() {
                if let Ok(c) = CString::new(line) {
                    // SAFETY: TAG and `c` are valid NUL-terminated C strings for the call.
                    unsafe {
                        __android_log_write(
                            ANDROID_LOG_INFO,
                            TAG.as_ptr() as *const c_char,
                            c.as_ptr(),
                        );
                    }
                }
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Install the logcat tracing subscriber. Idempotent; only the first call wins.
    pub fn init() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_writer(|| Writer)
                .with_ansi(false)
                .without_time()
                .with_max_level(Level::DEBUG)
                .try_init();
        });
    }
}
