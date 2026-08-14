//! A local store of signed transport bundles, resolvable by **engine name** (ADR 0013 §7).
//!
//! This is the last gap between "a transport is signed config plus a module" and "a server can put a
//! new transport on a client with no app upgrade". Until now `[transport.wasm]` required
//! `module = "/path/to.spkw"`, so the artifact had to already exist on disk by some means outside the
//! system — which meant the delivery step, the whole point, was left as an exercise.
//!
//! A store turns that into a lookup: bundles are installed under the engine name they were signed as,
//! and config refers to an engine rather than a path.
//!
//! Keyed by name, not by content hash. The signature already authenticates the bytes, so hashing
//! would add a second identity for the same thing while the useful question at dial time is "which
//! bundle implements engine X" — a question a content hash cannot answer.
//!
//! Two properties this file exists to guarantee:
//!
//! - **Anti-rollback survives restarts.** Floors live in a file next to the artifacts, so an attacker
//!   who can replay an old-but-correctly-signed bundle gains nothing by waiting for a restart. Both
//!   floors advance: the bundle's own version and the highest genome version inside it.
//! - **An engine name can never escape the store directory.** Names arrive from artifacts and config
//!   and are used to build paths, so `../../..` would be a file-write primitive. Names are validated
//!   before they touch the filesystem.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::bundle::{BundleError, BundleVerifier, VerifiedBundle};

/// File extension for a stored bundle artifact.
const BUNDLE_EXT: &str = "spkb";
/// Name of the persisted floor file inside the store directory.
const FLOORS_FILE: &str = "floors.toml";

/// Why a store operation failed.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The engine name is not usable as a path component.
    #[error("engine name `{0}` is not a valid store key (allowed: letters, digits, `.`, `-`, `_`; no leading `.`)")]
    BadName(String),
    /// No bundle is installed for this engine.
    #[error("no bundle installed for engine `{0}`")]
    NotInstalled(String),
    /// The stored bundle failed verification — a tampered or rolled-back artifact on disk.
    #[error("stored bundle for engine `{engine}`: {source}")]
    Invalid {
        engine: String,
        #[source]
        source: BundleError,
    },
    /// The delivered artifact failed verification.
    #[error("delivered bundle: {0}")]
    Rejected(#[from] BundleError),
    /// Filesystem trouble.
    #[error("bundle store I/O: {0}")]
    Io(#[from] io::Error),
}

/// The persisted anti-rollback state for one engine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Floor {
    /// Highest bundle version accepted so far.
    #[serde(default)]
    pub bundle: u32,
    /// Highest genome version accepted so far.
    #[serde(default)]
    pub genome: u64,
}

/// A directory of installed bundles plus their persisted floors.
pub struct BundleStore {
    dir: PathBuf,
}

impl BundleStore {
    /// A store rooted at `dir`. The directory is created on first install, not here, so merely
    /// constructing a store touches no filesystem.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Install a delivered bundle artifact, returning what it contained.
    ///
    /// Verification (signature, both floors, engine-name agreement, every genome) happens **before**
    /// anything is written, so a rejected bundle leaves the store exactly as it was. Only after the
    /// artifact is safely on disk are the floors advanced — the other order would refuse the very
    /// bundle we just accepted if the write failed.
    pub fn install(&self, artifact: &[u8]) -> Result<VerifiedBundle, StoreError> {
        // Verify against the floors we already hold, so a replayed old bundle is refused here rather
        // than at dial time.
        let floors = self.floors()?;
        // The engine name is inside the signed payload, so the floor lookup has to happen after a
        // first verification pass. Verify with zero floors to learn the name, then re-verify against
        // that engine's real floors — the second pass is what actually gates acceptance.
        let named = BundleVerifier::pinned().verify(artifact, 0, 0)?;
        let floor = floors.get(&named.engine).copied().unwrap_or_default();
        let verified = BundleVerifier::pinned().verify(artifact, floor.bundle, floor.genome)?;

        let engine = verified.engine.clone();
        let path = self.artifact_path(&engine)?;
        write_atomic(&self.dir, &path, artifact)?;

        self.bump(
            &engine,
            Floor {
                bundle: verified.version,
                genome: verified.max_genome_version(),
            },
        )?;
        Ok(verified)
    }

    /// Load the installed bundle for `engine`, re-verifying it against the persisted floors.
    ///
    /// Re-verifying on every load is deliberate: the artifact has been sitting in a file that other
    /// software on the machine may have modified, and the floors may have advanced since. A store read
    /// is not a reason to trust bytes.
    pub fn load(&self, engine: &str) -> Result<VerifiedBundle, StoreError> {
        let path = self.artifact_path(engine)?;
        let artifact = match std::fs::read(&path) {
            Ok(a) => a,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::NotInstalled(engine.to_owned()))
            }
            Err(e) => return Err(StoreError::Io(e)),
        };
        let floor = self.floors()?.get(engine).copied().unwrap_or_default();
        BundleVerifier::pinned()
            .verify(&artifact, floor.bundle, floor.genome)
            .map_err(|source| StoreError::Invalid {
                engine: engine.to_owned(),
                source,
            })
    }

    /// Whether a bundle is installed for `engine` (without verifying it).
    pub fn contains(&self, engine: &str) -> bool {
        self.artifact_path(engine)
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    /// The engines this store can actually serve, as `engine → bundle version`.
    ///
    /// This is what a client tells a server it already holds, so that the server can omit bytes it
    /// would otherwise re-send on every config fetch.
    ///
    /// Derived from the floors but **intersected with the artifacts on disk**, because the two can
    /// disagree in the direction that matters: floors only ever advance, so one survives its artifact
    /// being removed, and a floors-only list would claim an engine the store cannot load. The
    /// declaration is only a hint — a member whose bundle turns out to be missing is skipped, not
    /// fatal — but it should not be a hint we already know to be wrong.
    ///
    /// A missing or unreadable store is an empty map, not an error: having nothing to declare is the
    /// normal cold-start state, and it must not be able to fail a config fetch.
    pub fn installed(&self) -> BTreeMap<String, u32> {
        self.floors()
            .unwrap_or_default()
            .into_iter()
            .filter(|(engine, _)| self.contains(engine))
            .map(|(engine, floor)| (engine, floor.bundle))
            .collect()
    }

    /// The persisted floors, keyed by engine name.
    pub fn floors(&self) -> io::Result<BTreeMap<String, Floor>> {
        match std::fs::read_to_string(self.dir.join(FLOORS_FILE)) {
            Ok(s) => toml::from_str(&s).map_err(io::Error::other),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(e),
        }
    }

    /// Raise `engine`'s floors to at least `floor` (never lowers either component).
    fn bump(&self, engine: &str, floor: Floor) -> io::Result<()> {
        let mut floors = self.floors()?;
        let entry = floors.entry(engine.to_owned()).or_default();
        entry.bundle = entry.bundle.max(floor.bundle);
        entry.genome = entry.genome.max(floor.genome);
        let toml = toml::to_string(&floors).map_err(io::Error::other)?;
        // Atomic for the same reason the artifact is: a half-written floors file does not parse, and
        // since `floors()` propagates that error, a crash mid-write would break every later load and
        // install for *every* engine — losing the anti-rollback state this file exists to keep.
        write_atomic(&self.dir, &self.dir.join(FLOORS_FILE), toml.as_bytes())
    }

    /// The artifact path for `engine`, after validating the name is a safe path component.
    fn artifact_path(&self, engine: &str) -> Result<PathBuf, StoreError> {
        if !is_safe_name(engine) {
            return Err(StoreError::BadName(engine.to_owned()));
        }
        Ok(self.dir.join(format!("{engine}.{BUNDLE_EXT}")))
    }
}

/// Write `bytes` to `path` via a temp file in the same directory, then rename over the target.
///
/// Two properties matter here:
///
/// - **A crash never leaves a partial file.** `rename` is atomic within a filesystem, so a reader
///   sees either the old contents or the new ones — never a truncated artifact that would fail
///   verification, or a floors file that no longer parses.
/// - **Concurrent writers do not collide.** The temp name carries the process id and a counter, so
///   two installs of the same engine cannot interleave into one shared scratch path. A fixed
///   `<name>.tmp` would let them write over each other and rename whichever finished last, which
///   could publish a mixture of two artifacts.
///
/// `std::fs::rename` replaces an existing file on every platform we build for, Windows included
/// (`MoveFileExW` / `SetFileInformationByHandle`); the documented Windows caveat is about renaming
/// *onto a directory*, and these targets are always files. So there is deliberately no
/// remove-then-rename fallback — it would open a window where the bundle is simply absent.
fn write_atomic(dir: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    // Best-effort cleanup: leaving a stray temp file behind on a failed rename is untidy but
    // harmless (a unique name is never read back), while failing to report the real error is not.
    if let Err(e) = std::fs::write(&tmp, bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Whether `name` is safe to use as a single path component.
///
/// Deliberately a strict allow-list rather than a scan for `..` and separators: engine names are
/// short identifiers, an allow-list cannot be outwitted by an encoding nobody thought of, and the
/// cost of rejecting an exotic-but-innocent name is that somebody renames their transport.
fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// The default store directory: `<parent>/bundles`, alongside whatever config dir the caller uses.
pub fn default_dir(parent: &Path) -> PathBuf {
    parent.join("bundles")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::engine::bundle::{self, Bundle};
    use crate::transport::engine::Genome;
    use crate::transport::wasm::testutil::dev_keypair;
    use ring::signature::Ed25519KeyPair;
    use std::sync::atomic::{AtomicU32, Ordering};

    const ENGINE: &str = "bip324";

    fn temp_dir(tag: &str) -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!(
            "spark-bundle-store-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).expect("create temp dir");
        d
    }

    fn genome(engine: &str, version: u64) -> Vec<u8> {
        let mut g = Genome::new("plan", engine, Default::default(), vec![9]);
        g.version = version;
        g.encode().expect("encode")
    }

    /// A signed bundle artifact for `engine` at bundle version `bv` carrying a genome at `gv`.
    fn artifact(kp: &Ed25519KeyPair, engine: &str, bv: u32, gv: u64) -> Vec<u8> {
        let b = Bundle::new(
            engine,
            vec![genome(engine, gv)],
            Some(vec![0, 97, 115, 109]),
        );
        let payload = bundle::signing_payload(engine, bv, &b).expect("payload");
        let sig = kp.sign(&payload);
        let mut s = [0u8; 64];
        s.copy_from_slice(sig.as_ref());
        bundle::build_artifact(engine, bv, &b, &s).expect("artifact")
    }

    #[test]
    fn install_then_load_resolves_by_engine_name() {
        let dir = temp_dir("hit");
        let store = BundleStore::new(&dir);
        let kp = dev_keypair();

        assert!(!store.contains(ENGINE), "nothing installed yet");
        let installed = store
            .install(&artifact(&kp, ENGINE, 2, 5))
            .expect("install a correctly signed bundle");
        assert_eq!(installed.engine, ENGINE);
        assert!(store.contains(ENGINE));

        // The resolution a dial does: name in, verified plans out. No path anywhere.
        let loaded = store.load(ENGINE).expect("load by name");
        assert_eq!(loaded.version, 2);
        assert_eq!(loaded.genomes.len(), 1);
        assert_eq!(loaded.max_genome_version(), 5);
        assert!(loaded.wasm.is_some(), "the module came with the plans");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The producer and the consumer agree: what `sign-module bundle` emits is exactly what the
    /// delivery path installs and loads.
    ///
    /// The other tests here hand-assemble artifacts, which proves the *store* works but would keep
    /// working if `sign_bundle` drifted from it — and the tool is the only way a real artifact is ever
    /// made. This is the seam that has to hold for a module to reach a client at all.
    #[cfg(feature = "module-signer")]
    #[test]
    fn a_tool_signed_bundle_installs_and_loads() {
        let dir = temp_dir("tool");
        let store = BundleStore::new(&dir);

        let b = Bundle::new(ENGINE, vec![genome(ENGINE, 4)], Some(vec![0, 97, 115, 109]))
            .with_capabilities(vec!["host_rand".to_string()]);
        let artifact =
            bundle::sign_bundle(&dev_keypair(), ENGINE, 7, &b).expect("the tool signs a bundle");

        let installed = store
            .install(&artifact)
            .expect("install a tool-signed bundle");
        assert_eq!(installed.engine, ENGINE);
        assert_eq!(installed.version, 7);

        let loaded = store.load(ENGINE).expect("load by name");
        assert_eq!(loaded.max_genome_version(), 4);
        assert_eq!(
            loaded.capabilities.as_deref(),
            Some(["host_rand".to_string()].as_slice()),
            "the capability grant survives the round trip inside the signature"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// What a client declares to the server must be what it can actually serve.
    ///
    /// Floors and artifacts can disagree in the direction that matters: floors only ever advance, so
    /// one outlives its artifact. A floors-only declaration would tell the server "don't send me
    /// bip324, I have it" about an engine the store can no longer load — turning a cheap re-send into
    /// a silently skipped pool member.
    #[test]
    fn installed_declares_only_engines_still_on_disk() {
        let dir = temp_dir("installed");
        let store = BundleStore::new(&dir);
        assert!(
            store.installed().is_empty(),
            "a cold store declares nothing"
        );

        store
            .install(&artifact(&dev_keypair(), ENGINE, 3, 1))
            .expect("install");
        assert_eq!(
            store.installed(),
            [(ENGINE.to_string(), 3u32)]
                .into_iter()
                .collect::<BTreeMap<_, _>>(),
            "an installed engine is declared at its bundle version"
        );

        // Remove the artifact but leave the floors — the state a floors-only view would misreport.
        std::fs::remove_file(dir.join(format!("{ENGINE}.{BUNDLE_EXT}"))).expect("remove artifact");
        assert!(
            !store.floors().expect("floors").is_empty(),
            "the floor survives the artifact, which is the whole hazard"
        );
        assert!(
            store.installed().is_empty(),
            "an engine whose artifact is gone must not be declared"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_bundle_fails_loud() {
        let dir = temp_dir("miss");
        let store = BundleStore::new(&dir);
        assert!(
            matches!(store.load("nope"), Err(StoreError::NotInstalled(e)) if e == "nope"),
            "a cache miss names the engine rather than degrading to something else"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The property that makes the floors worth persisting: a fresh `BundleStore` over the same
    /// directory — i.e. a restarted process — still refuses a replayed older bundle.
    #[test]
    fn anti_rollback_survives_a_restart() {
        let dir = temp_dir("rollback");
        let kp = dev_keypair();

        BundleStore::new(&dir)
            .install(&artifact(&kp, ENGINE, 9, 20))
            .expect("install v9/g20");

        // A new store instance reads the floors off disk, as a restarted client would.
        let restarted = BundleStore::new(&dir);
        let floor = restarted.floors().expect("floors")[ENGINE];
        assert_eq!((floor.bundle, floor.genome), (9, 20));

        // Correctly signed, but older on both axes.
        let err = restarted
            .install(&artifact(&kp, ENGINE, 7, 20))
            .expect_err("an older bundle version must be refused after restart");
        assert!(matches!(err, StoreError::Rejected(BundleError::Verify(_))));

        // Same bundle version, stale genome — the genome floor is enforced independently.
        let err = restarted
            .install(&artifact(&kp, ENGINE, 10, 3))
            .expect_err("a stale genome must be refused even in a newer bundle");
        assert!(matches!(
            err,
            StoreError::Rejected(BundleError::GenomeRollback { .. })
        ));

        // Moving forward on both axes is accepted, and advances the floors again.
        restarted
            .install(&artifact(&kp, ENGINE, 10, 25))
            .expect("a newer bundle installs");
        let floor = restarted.floors().expect("floors")[ENGINE];
        assert_eq!((floor.bundle, floor.genome), (10, 25));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_rejected_install_leaves_the_store_untouched() {
        let dir = temp_dir("atomic");
        let store = BundleStore::new(&dir);
        let kp = dev_keypair();

        store
            .install(&artifact(&kp, ENGINE, 5, 5))
            .expect("install");
        let good = std::fs::read(dir.join(format!("{ENGINE}.{BUNDLE_EXT}"))).expect("read");

        // Tamper with a delivered artifact and try to install it.
        let mut bad = artifact(&kp, ENGINE, 6, 6);
        let i = bad.len() / 2;
        bad[i] ^= 0xFF;
        assert!(store.install(&bad).is_err(), "tampered install refused");

        assert_eq!(
            std::fs::read(dir.join(format!("{ENGINE}.{BUNDLE_EXT}"))).expect("read"),
            good,
            "the previously installed artifact is untouched"
        );
        let floor = store.floors().expect("floors")[ENGINE];
        assert_eq!((floor.bundle, floor.genome), (5, 5), "floors did not move");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// End to end: a bundle installed with a capability grant produces a module that actually holds
    /// only those imports. This is the property a third-party transport depends on — everything else
    /// in the trust story (signature, anti-rollback, engine naming) says *who* wrote the code, and
    /// this says *what it may do*.
    #[test]
    fn an_installed_bundle_scopes_the_module_it_carries() {
        use crate::transport::wasm::{testutil::XOR_WAT, TransformModule};

        let dir = temp_dir("caps");
        let kp = dev_keypair();
        let wasm = wat::parse_str(XOR_WAT).expect("assemble fixture");

        // Grant only `host_hash` — the XOR fixture imports `host_rand`, so this is deliberately the
        // wrong grant and the module must refuse to instantiate.
        let b = Bundle::new(ENGINE, vec![genome(ENGINE, 1)], Some(wasm.clone()))
            .with_capabilities(vec!["host_hash".to_owned()]);
        let payload = bundle::signing_payload(ENGINE, 1, &b).expect("payload");
        let sig = kp.sign(&payload);
        let mut sg = [0u8; 64];
        sg.copy_from_slice(sig.as_ref());
        let art = bundle::build_artifact(ENGINE, 1, &b, &sg).expect("artifact");

        let store = BundleStore::new(&dir);
        let installed = store.install(&art).expect("install");
        assert_eq!(
            installed.capabilities.as_deref(),
            Some(&["host_hash".to_owned()][..])
        );

        let loaded = store.load(ENGINE).expect("load");
        let module = TransformModule::load_scoped(
            loaded.wasm.as_deref().expect("wasm"),
            loaded.capabilities.clone(),
        )
        .expect("compile");
        assert!(
            module.instantiate().map(|_| ()).is_err(),
            "the signed grant withheld host_rand, so this module must not instantiate"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Concurrent installs of the same engine must not interleave through a shared scratch file.
    /// With a fixed `<name>.tmp` two writers race on one path and the rename can publish a mixture;
    /// with per-write temp names whichever lands last wins cleanly, and the result always verifies.
    #[test]
    fn concurrent_installs_of_one_engine_do_not_corrupt_the_artifact() {
        let dir = temp_dir("concurrent");
        let kp = dev_keypair();
        // Same bundle version from every thread, so none is a rollback against the others and they
        // genuinely contend on the write rather than being rejected by the floor.
        let artifacts: Vec<Vec<u8>> = (0..8).map(|_| artifact(&kp, ENGINE, 1, 1)).collect();

        std::thread::scope(|s| {
            for a in &artifacts {
                let dir = dir.clone();
                s.spawn(move || {
                    // A rejected install is fine here (floors advance under contention); a corrupt
                    // one is not, which is what the load below checks.
                    let _ = BundleStore::new(&dir).install(a);
                });
            }
        });

        let loaded = BundleStore::new(&dir)
            .load(ENGINE)
            .expect("the installed artifact verifies after concurrent writes");
        assert_eq!(loaded.engine, ENGINE);
        assert_eq!(loaded.genomes.len(), 1);

        // No scratch files survive a successful run.
        let strays: Vec<_> = std::fs::read_dir(&dir)
            .expect("read store dir")
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .filter(|n| n.contains("tmp"))
            .collect();
        assert!(strays.is_empty(), "temp files left behind: {strays:?}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// An engine name is used to build a path, so a traversal attempt must be refused outright rather
    /// than sanitized into something that "looks" safe.
    #[test]
    fn an_engine_name_cannot_escape_the_store_directory() {
        let dir = temp_dir("traversal");
        let store = BundleStore::new(&dir);
        for name in [
            "../evil",
            "..",
            ".",
            "a/b",
            "a\\b",
            ".hidden",
            "",
            "with space",
        ] {
            assert!(
                matches!(store.load(name), Err(StoreError::BadName(_))),
                "`{name}` must be refused as a store key"
            );
        }
        assert!(is_safe_name("bip324"));
        assert!(is_safe_name("obfs-xor_2.1"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
