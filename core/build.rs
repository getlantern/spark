//! Build script for `spark-core`.
//!
//! Two jobs, both about the values this crate reads with `option_env!` — the parameters that cannot
//! come from fetched config because they are what the pre-config phase needs in order to fetch
//! (the bootstrap DNS-tunnel race member, the diagnostics endpoint) or to identify the build.
//!
//! **1. Make changing them actually rebuild.** `option_env!` is expanded at compile time, but cargo
//! has no way to know a source file depends on an environment variable — so without the
//! `rerun-if-env-changed` lines below, setting `SPARK_BOOTSTRAP_DNS_ZONE` and rebuilding into a warm
//! target dir silently produces a binary with the OLD value baked in. That failure is invisible: the
//! build succeeds, the binary looks right, and the member is simply absent. CI never hit it (fresh
//! checkouts), which is precisely why it could sit unnoticed for anyone building a release by hand.
//!
//! **2. Say so when a release build is missing one.** A `cargo:warning` on a release build with no
//! bootstrap zone, because "shipped without the last-resort transport" should not be a silent
//! outcome. Debug builds stay quiet — nobody pins these locally.

fn main() {
    // Every build-time-pinned value this crate reads. Adding an `option_env!` anywhere in `core`
    // means adding its name here, or that value gets stale-cached exactly as described above.
    const PINNED: &[&str] = &[
        "SPARK_BOOTSTRAP_DNS_ZONE",
        "SPARK_BOOTSTRAP_DNS_PUBKEY",
        "SPARK_BOOTSTRAP_DNS_RESOLVERS",
        "SPARK_OTEL_ENDPOINT",
        "SPARK_OTEL_INGEST_KEY",
        "SPARK_MODULE_PUBKEY_HEX",
        "SPARK_GIT_SHA",
    ];
    for var in PINNED {
        println!("cargo:rerun-if-env-changed={var}");
        // Re-emit as `rustc-env`, which is the half that actually works. `rerun-if-env-changed`
        // alone only reruns THIS SCRIPT; cargo decides whether to recompile the crate from whether
        // the script's *output* changed, and a script that merely prints the same rerun lines every
        // time has not changed its output. So the crate keeps its previously-expanded `option_env!`
        // — stale, silently, with `Compiling spark-core` printed to make it look otherwise (that
        // line is the build script, not the crate).
        //
        // Echoing the value into the output fixes both halves at once: the output now differs when
        // the value differs, which forces the recompile, and `option_env!` reads the value from
        // here. Verified with a canary zone that lands in the binary only with this line present.
        if let Some(value) = std::env::var_os(var) {
            println!("cargo:rustc-env={var}={}", value.to_string_lossy());
        }
    }

    // `SPARK_GIT_SHA` stamps the OTLP resource block, so a field report says which build produced
    // it. Honour an externally supplied value first (CI knows the real ref; a tarball build has no
    // git dir at all), then fall back to asking git, then to "unknown" — `diag` already treats that
    // as a legitimate value, so a build outside a checkout must not fail here.
    if std::env::var_os("SPARK_GIT_SHA").is_none() {
        // Watch the files a commit/checkout touches, or the sha goes stale exactly like the env
        // vars above — and far more quietly, since nothing about it is an env var to change.
        //
        // Emitting ANY `rerun-if-*` line (the loop above emits several) switches off cargo's
        // default "re-run this script when any file in the package changes". From then on the
        // script runs only when a listed condition fires, so a moved HEAD re-ran nothing: cargo
        // reused the previous run's cached output, `git_sha()` never executed, and the crate kept
        // an `option_env!` expansion from an earlier commit. Observed: a local build stamped
        // `9bf9a4e` while containing code that only exists as of `8af3cce` — current binary,
        // previous label, on the one field whose entire purpose is naming the build.
        emit_git_rerun();
        if let Some(sha) = git_sha() {
            println!("cargo:rustc-env=SPARK_GIT_SHA={sha}");
        }
    }

    // Only release builds are shippable, so only they are worth warning about.
    if std::env::var("PROFILE").as_deref() == Ok("release")
        && std::env::var_os("SPARK_BOOTSTRAP_DNS_ZONE").is_none()
    {
        println!(
            "cargo:warning=SPARK_BOOTSTRAP_DNS_ZONE is unset — this release build has no bootstrap \
             dns-tunnel race member, so config-fetch runs on direct + proxyless + fronted only. \
             Set SPARK_BOOTSTRAP_DNS_ZONE/_PUBKEY/_RESOLVERS to include it."
        );
    }
}

/// Tell cargo which git files invalidate the stamped sha.
///
/// `HEAD` covers checkouts and detached-HEAD moves (the file holds the sha directly). When `HEAD` is
/// a symbolic ref, the ref file it names must be watched too — committing on a branch rewrites
/// `refs/heads/<branch>` and leaves `HEAD` itself untouched, which is the common case and the one
/// that bit us. Absolute paths, because cargo resolves relative ones against the package dir
/// (`core/`), not the workspace root.
///
/// Silent no-op outside a checkout: a tarball build legitimately has no git dir, and `SPARK_GIT_SHA`
/// falls through to `"unknown"` rather than failing.
fn emit_git_rerun() {
    let Some(git_dir) = run_git(&["rev-parse", "--absolute-git-dir"]) else {
        return;
    };
    println!("cargo:rerun-if-changed={git_dir}/HEAD");
    // Fails on a detached HEAD, where `HEAD` above is already the whole story.
    if let Some(head_ref) = run_git(&["symbolic-ref", "-q", "HEAD"]) {
        println!("cargo:rerun-if-changed={git_dir}/{head_ref}");
    }
}

/// Run `git` with `args` and return trimmed stdout, or `None` if git is absent, errors, or the
/// output is empty.
fn run_git(args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// The short HEAD sha, or `None` outside a checkout / without git. Never fails the build.
fn git_sha() -> Option<String> {
    run_git(&["rev-parse", "--short", "HEAD"])
}
