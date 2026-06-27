# Spark Android — Phase 4 (Gradle cargo-ndk wiring) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Build `libspark_android.so` automatically from the Rust crate during the Gradle build via cargo-ndk, so a clean checkout produces the native lib with no manual step (today the `.so` is built by a hand-run `cargo ndk …` and only bundled by Gradle).

**Architecture:** A Gradle `Exec` task (`cargoNdkBuild`) runs `cargo ndk -t arm64-v8a -t x86_64 -P 24 -o <jniLibs> build --release -p spark-android` (from the `platforms/android` crate dir), then deletes cargo-ndk's stray `libtun_rs-*.so` byproduct (we statically link it). `preBuild` depends on it, so the `.so` exists before AGP merges `src/main/jniLibs`. The `.so` stays gitignored (already is).

**Tech Stack:** Gradle (Groovy DSL), cargo-ndk, Android NDK 28.2.13676358 (`ANDROID_NDK_HOME`).

**Prerequisites (developer machine):** `cargo install cargo-ndk`; NDK 28.2 installed; Rust Android targets (`rustup target add aarch64-linux-android x86_64-linux-android`). The task fails with a clear message if cargo-ndk is missing.

---

## Task 1: cargoNdkBuild Gradle task + preBuild hook

**Files:** Modify `platforms/android/demo/app/build.gradle`.

- [ ] **Step 1:** Add, after the `android { … }` block:
```groovy
// Build the Rust JNI lib (libspark_android.so) into src/main/jniLibs via cargo-ndk so a clean
// build produces the native lib with no manual step. Requires cargo-ndk + the Android NDK.
def rustCrateDir = rootProject.projectDir.parentFile        // platforms/android (the spark-android crate)
def repoRootDir = rustCrateDir.parentFile.parentFile        // repo root (workspace root)
def jniLibsDir = new File(projectDir, 'src/main/jniLibs')
def ndkVersion4Cargo = '28.2.13676358'

tasks.register('cargoNdkBuild', Exec) {
    group = 'build'
    description = 'Cross-compiles libspark_android.so for arm64-v8a + x86_64 via cargo-ndk.'
    workingDir rustCrateDir
    environment 'ANDROID_NDK_HOME',
        System.getenv('ANDROID_NDK_HOME') ?: "${android.sdkDirectory}/ndk/${ndkVersion4Cargo}"
    // -P is cargo-ndk's --platform (Android API level); derive from minSdk so they can't drift.
    commandLine 'cargo', 'ndk',
        '-t', 'arm64-v8a', '-t', 'x86_64', '-P', "${android.defaultConfig.minSdk}",
        '-o', jniLibsDir.absolutePath,
        'build', '--release', '-p', 'spark-android'
    // Up-to-date check: re-run when the Android crate, the core sources/manifest, or the resolved
    // dependency set (Cargo.lock) change — so plain Kotlin/UI edits don't shell out to cargo.
    inputs.dir new File(rustCrateDir, 'src')
    inputs.file new File(rustCrateDir, 'Cargo.toml')
    inputs.dir new File(repoRootDir, 'core/src')
    inputs.file new File(repoRootDir, 'core/Cargo.toml')
    inputs.file new File(repoRootDir, 'Cargo.lock')
    outputs.dir jniLibsDir
    doFirst {
        // Cross-platform PATH scan (no shell dependency) for cargo-ndk.
        def exeNames = ['cargo-ndk', 'cargo-ndk.exe']
        def onPath = (System.getenv('PATH') ?: '').split(File.pathSeparator).any { dir ->
            exeNames.any { new File(dir, it).canExecute() }
        }
        if (!onPath) {
            throw new GradleException('cargo-ndk not found on PATH. Run `cargo install cargo-ndk` and ' +
                'ensure ~/.cargo/bin is on PATH (or build the .so manually per platforms/android/README.md).')
        }
    }
    doLast {
        // Drop cargo-ndk's stray copy of tun-rs's dylib byproduct (statically linked into our .so).
        ['arm64-v8a', 'x86_64'].each { abi ->
            fileTree(dir: new File(jniLibsDir, abi), include: 'libtun_rs-*.so').each { it.delete() }
        }
    }
}

// Produce the .so before AGP reads/merges src/main/jniLibs.
tasks.named('preBuild').configure { dependsOn 'cargoNdkBuild' }
```
- [ ] **Step 2:** Update the stale comment in `buildTypes { debug { … } }` (it currently says "already release-built by cargo-ndk; nothing to do") to note the task now builds it.
- [ ] **Step 3:** `cd platforms/android/demo && ./gradlew :app:cargoNdkBuild` — Expected: cargo-ndk compiles and writes `src/main/jniLibs/{arm64-v8a,x86_64}/libspark_android.so`, with no `libtun_rs-*.so` left. (First run is slow — compiles the core for two ABIs.)
- [ ] **Step 4:** Commit `build(android): build libspark_android.so via cargo-ndk in Gradle`.

## Task 2: Clean-build verification (the gate)

- [ ] **Step 1:** Remove the prebuilt artifacts to prove the task regenerates them: `rm -rf platforms/android/demo/app/src/main/jniLibs`.
- [ ] **Step 2:** `cd platforms/android/demo && ./gradlew clean assembleDebug` — Expected: `cargoNdkBuild` runs, the `.so`s are regenerated, BUILD SUCCESSFUL, and the APK contains `lib/arm64-v8a/libspark_android.so` + `lib/x86_64/libspark_android.so` (verify with `unzip -l app/build/outputs/apk/debug/app-debug.apk | grep libspark_android`).
- [ ] **Step 3:** Install on the emulator and confirm the app still loads the native lib and connects (the JNI `System.loadLibrary("spark_android")` resolves; toggle → CONNECTED). **Device gate.**
- [ ] **Step 4 (incremental check):** Run `./gradlew assembleDebug` again with no Rust change — `cargoNdkBuild` should be `UP-TO-DATE` (inputs unchanged). Touch a Kotlin file and rebuild — `cargoNdkBuild` stays UP-TO-DATE (only Kotlin recompiles). Touch `platforms/android/Cargo.toml` and rebuild — `cargoNdkBuild` re-runs.
- [ ] **Step 5:** Commit (if any tweaks were needed) `chore(android): verify clean cargo-ndk build`.

## Phase 4 completion gate
A clean checkout (no prebuilt `.so`) builds and runs end-to-end with a single `./gradlew assembleDebug`; cargo-ndk is invoked by Gradle; incremental Kotlin builds don't re-run cargo. PR opened, Copilot loop run.

## Notes
- CI implications: any CI that builds the APK now needs cargo-ndk + the NDK + Rust Android targets. If the repo's CI doesn't build the Android APK today (it builds the Rust workspace / size checks), no CI change is needed; document the local prerequisite in `platforms/android/README.md`.
- Optional follow-up (not in this plan): rename the `demo/` module to `app/`. Deferred — it churns paths (settings.gradle, jniLibs, CI) for no functional gain; do it only when the module graph grows.
