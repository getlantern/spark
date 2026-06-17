//! `spark-android` — the JNI library (`libspark_android.so`) the Android `VpnService` loads via
//! `System.loadLibrary("spark_android")`.
//!
//! The bridge is deliberately primitive-only (fd + mtu as `jint`), so it needs no `jni` crate:
//! the `VpnService` establishes the tunnel, configures routing, and excludes the app's own
//! sockets (`addDisallowedApplication`), then hands the TUN fd here to run the data path. Stop
//! is signalled from `onDestroy`. The actual run/stop logic lives in [`spark_core::android`].
//!
//! On non-Android targets these symbols are `cfg`-d out, so the crate builds as an empty cdylib
//! and stays in the workspace's green-checked set without affecting desktop builds.

// Kotlin side (package org.getlantern.spark):
//   object SparkBridge {
//       init { System.loadLibrary("spark_android") }
//       // addr = the tun IPv4 packed big-endian into an Int (e.g. 10.0.0.1 -> 0x0A000001);
//       // it must equal the address passed to VpnService.Builder.addAddress(addr, prefix), and
//       // `prefix` must cover addr+1 (the system stack's synthetic gateway). systemStack: 1 = the
//       // kernel-TCP "system" stack, 0 = the userspace (smoltcp) stack.
//       external fun nativeRun(fd: Int, mtu: Int, addr: Int, prefix: Int, systemStack: Int): Int
//       external fun nativeStop()
//   }
#[cfg(target_os = "android")]
mod jni {
    use std::os::raw::c_void;

    /// JNI `jint`.
    type JInt = i32;

    /// `SparkBridge.nativeRun(fd, mtu, addr, prefix, systemStack)` — adopt the `VpnService` TUN `fd`
    /// and run the tunnel with the chosen netstack, blocking the calling thread until [`nativeStop`]
    /// (or the data path exits). Returns 0 on a clean stop, -1 on error.
    ///
    /// `addr` is the tun IPv4 address packed big-endian into a `jint`; the system stack binds its
    /// kernel listener there and derives its gateway as `addr + 1` (so `prefix` must include it).
    #[no_mangle]
    pub extern "system" fn Java_org_getlantern_spark_SparkBridge_nativeRun(
        _env: *mut c_void,
        _class: *mut c_void,
        fd: JInt,
        mtu: JInt,
        addr: JInt,
        prefix: JInt,
        system_stack: JInt,
    ) -> JInt {
        crate::logcat::init();
        let config = config(addr, prefix, system_stack);
        match spark_core::fd_tunnel::run_tunnel_with_config(fd, mtu as u16, config) {
            Ok(()) => 0,
            Err(_) => -1,
        }
    }

    /// Build the run config from the JNI primitives: direct forwarding (Android excludes the app's
    /// own UID from the tun, so upstream dials bypass it) with the tun address + chosen stack.
    fn config(addr: JInt, prefix: JInt, system_stack: JInt) -> spark_core::config::Config {
        use spark_core::config::{Config, StackKind};
        let mut config = Config::default();
        config.tun.addr = std::net::Ipv4Addr::from(addr as u32);
        config.tun.prefix = prefix as u8;
        config.tun.stack = if system_stack != 0 {
            StackKind::System
        } else {
            StackKind::Userspace
        };
        config
    }

    /// `SparkBridge.nativeStop()` — signal the running tunnel to stop (from `onDestroy`).
    #[no_mangle]
    pub extern "system" fn Java_org_getlantern_spark_SparkBridge_nativeStop(
        _env: *mut c_void,
        _class: *mut c_void,
    ) {
        spark_core::fd_tunnel::stop();
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
