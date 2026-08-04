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
        std::fs::create_dir_all(&self.dir)?;
        // Temp-then-rename so a crash mid-write cannot leave a truncated artifact that would fail
        // verification on the next load and strand the transport.
        let tmp = path.with_extension(format!("{BUNDLE_EXT}.tmp"));
        std::fs::write(&tmp, artifact)?;
        std::fs::rename(&tmp, &path)?;

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
        std::fs::create_dir_all(&self.dir)?;
        std::fs::write(self.dir.join(FLOORS_FILE), toml)
    }

    /// The artifact path for `engine`, after validating the name is a safe path component.
    fn artifact_path(&self, engine: &str) -> Result<PathBuf, StoreError> {
        if !is_safe_name(engine) {
            return Err(StoreError::BadName(engine.to_owned()));
        }
        Ok(self.dir.join(format!("{engine}.{BUNDLE_EXT}")))
    }
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
