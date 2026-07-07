import java.io.File

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    // MUST differ from the app's applicationId (org.getlantern.spark) so the merged R class
    // and manifest don't clash. The migrated Kotlin keeps package org.getlantern.spark for the
    // JNI symbols (Java_org_getlantern_spark_SparkBridge_*); only the library namespace differs.
    namespace = "org.getlantern.spark.vpn"
    compileSdk = 36

    defaultConfig {
        minSdk = 21

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
        // Match the ABIs cargoNdkBuild produces into src/main/jniLibs.
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

// Build the Rust JNI lib (libspark_android.so) into src/main/jniLibs via cargo-ndk so a clean
// build produces the native lib with no manual step. Ported from
// platforms/android/demo/app/build.gradle's cargoNdkBuild. Requires cargo-ndk + the Android NDK.
//
// From this module dir (gui-tauri/tauri-plugin-spark-vpn/android) the repo layout is:
//   ../../../                      -> repo root (cargo workspace root)
//   ../../../platforms/android     -> the spark-android crate
val repoRootDir: File = projectDir.parentFile.parentFile.parentFile
val rustCrateDir = File(repoRootDir, "platforms/android")
val jniLibsDir = File(projectDir, "src/main/jniLibs")
val ndkVersionForCargo = "28.2.13676358"
val ndkHome: String = System.getenv("ANDROID_NDK_HOME")
    ?: "${android.sdkDirectory}/ndk/$ndkVersionForCargo"

val cargoNdkBuild by tasks.registering(Exec::class) {
    group = "build"
    description = "Cross-compiles libspark_android.so for arm64-v8a + x86_64 via cargo-ndk."
    workingDir = rustCrateDir
    environment("ANDROID_NDK_HOME", ndkHome)
    // -P is cargo-ndk's --platform (Android API level); derive it from minSdk so the two can't drift.
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a", "-t", "x86_64", "-P", "${android.defaultConfig.minSdk}",
        "-o", jniLibsDir.absolutePath,
        // --locked: don't mutate Cargo.lock (declared as an input) — reproducible builds.
        "build", "--release", "--locked", "-p", "spark-android"
    )
    // Up-to-date check: re-run only when the Android crate, the core sources/manifest, or the
    // resolved dependency set (Cargo.lock) change.
    inputs.dir(File(rustCrateDir, "src"))
    inputs.file(File(rustCrateDir, "Cargo.toml"))
    inputs.dir(File(repoRootDir, "core/src"))
    inputs.file(File(repoRootDir, "core/Cargo.toml"))
    inputs.file(File(repoRootDir, "Cargo.lock"))
    outputs.dir(jniLibsDir)
    doFirst {
        // Fail fast with a clear message for the common missing-NDK case.
        if (!File(ndkHome).isDirectory) {
            throw GradleException(
                "Android NDK not found at '$ndkHome'. Install NDK $ndkVersionForCargo " +
                    "(sdkmanager \"ndk;$ndkVersionForCargo\") or set ANDROID_NDK_HOME."
            )
        }
    }
    doLast {
        // Drop cargo-ndk's stray copy of tun-rs's dylib byproduct (statically linked into our .so).
        listOf("arm64-v8a", "x86_64").forEach { abi ->
            fileTree(File(jniLibsDir, abi)) { include("libtun_rs-*.so") }.forEach { it.delete() }
        }
    }
}

// Produce the .so before AGP reads/merges src/main/jniLibs.
tasks.named("preBuild").configure { dependsOn(cargoNdkBuild) }

dependencies {
    implementation("androidx.core:core-ktx:1.9.0")
    implementation("androidx.appcompat:appcompat:1.6.0")
    // SparkState (VpnState.kt) exposes tunnel state as a StateFlow.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
    implementation(project(":tauri-android"))
}
