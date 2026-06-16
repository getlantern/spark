package org.getlantern.spark

/**
 * JNI bridge to libspark_android.so (built by cargo-ndk from the `spark-android` crate). The
 * native symbols are `Java_org_getlantern_spark_SparkBridge_*`, so this object MUST stay in
 * package `org.getlantern.spark` with this name.
 */
object SparkBridge {
    init {
        System.loadLibrary("spark_android")
    }

    /** Adopt the VpnService TUN [fd] (ownership transferred) and run the tunnel with [mtu].
     *  Blocks the calling thread until [nativeStop]. Returns 0 on clean stop, -1 on error. */
    external fun nativeRun(fd: Int, mtu: Int): Int

    /** Signal a running [nativeRun] to stop. */
    external fun nativeStop()
}
