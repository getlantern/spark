// Android library module wrapping the spark-ffi control-plane binding: the cargo-ndk-built cdylib
// (jniLibs/) + the UniFFI-generated Kotlin (kotlin/). Run ./build-android.sh first to populate
// both, then a consuming project includes this module (settings.gradle: `include(":spark-ffi")`,
// `project(":spark-ffi").projectDir = file("…/spark-ffi/android")`) and depends on it. To produce a
// standalone .aar, add a settings.gradle.kts (with the AGP/Kotlin plugin versions in
// pluginManagement) + a gradle wrapper, then `./gradlew assembleRelease`.
//
// Versions track platforms/android/demo (AGP 8.9.x, Kotlin 2.1.x, minSdk 24).
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.getlantern.spark.ffi"
    compileSdk = 35

    defaultConfig {
        minSdk = 24
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    sourceSets["main"].apply {
        // The UniFFI-generated Kotlin (uniffi/spark_ffi/spark_ffi.kt).
        java.srcDir("kotlin")
        // libspark_ffi.so per ABI, loaded by the generated bindings via System.loadLibrary.
        jniLibs.srcDir("jniLibs")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    // UniFFI's Kotlin bindings call into the .so through JNA (the @aar variant ships JNA's own
    // native libs for Android).
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    // The generated `suspend` methods (async control calls) use kotlinx coroutines.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
}
