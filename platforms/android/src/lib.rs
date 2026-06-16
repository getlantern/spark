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
//       external fun nativeRun(fd: Int, mtu: Int): Int   // blocks until nativeStop / exit
//       external fun nativeStop()
//   }
#[cfg(target_os = "android")]
mod jni {
    use std::os::raw::c_void;

    /// JNI `jint`.
    type JInt = i32;

    /// `SparkBridge.nativeRun(fd, mtu)` — adopt the `VpnService` TUN `fd` and run the tunnel,
    /// blocking the calling thread until [`nativeStop`] (or the data path exits). Returns 0 on a
    /// clean stop, -1 on error.
    #[no_mangle]
    pub extern "system" fn Java_org_getlantern_spark_SparkBridge_nativeRun(
        _env: *mut c_void,
        _class: *mut c_void,
        fd: JInt,
        mtu: JInt,
    ) -> JInt {
        match spark_core::android::run_tunnel(fd, mtu as u16) {
            Ok(()) => 0,
            Err(_) => -1,
        }
    }

    /// `SparkBridge.nativeStop()` — signal the running tunnel to stop (from `onDestroy`).
    #[no_mangle]
    pub extern "system" fn Java_org_getlantern_spark_SparkBridge_nativeStop(
        _env: *mut c_void,
        _class: *mut c_void,
    ) {
        spark_core::android::stop();
    }
}
