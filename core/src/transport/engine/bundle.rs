//! Signed transport bundles — one delivery unit for an engine and the opening plans that drive it
//! (ADR 0013 §7).
//!
//! Two things were being delivered by two different mechanisms with two different trust stories. A
//! module arrived as a signed `.spkw` (Ed25519, pinned key, monotonic version floor) while a genome
//! arrived as hex in a config file, carrying a `version` field that [`Genome`] itself documents as
//! "carried but not yet enforced". So the code that could ship arbitrary WebAssembly was carefully
//! authenticated and the code that told it *what protocol to speak* was not.
//!
//! A bundle closes that: the genomes and (optionally) the module that realizes them are signed
//! together, by the same key, under the same anti-rollback discipline. Signing them together also
//! removes a mismatch that signing them apart cannot — a genome is only meaningful against the engine
//! it was authored for, and here the engine name is part of what was signed.
//!
//! What gets checked, in order, before any content is acted on:
//!  1. the Ed25519 signature over the whole payload, against the key pinned in this binary;
//!  2. the bundle's monotonic version, against the caller's floor (a correctly signed *old* bundle is
//!     still an attack);
//!  3. the envelope schema version — postcard is positional, so a mismatch cannot be reinterpreted;
//!  4. that the engine the bundle claims equals the name it was **signed** as, so nobody can ship
//!     plans addressed to an engine they do not hold a signature for;
//!  5. every genome: decodable, right schema, addressed to this engine, and **at or above the genome
//!     floor** — the enforcement `Genome::version` was written for and never had.
//!
//! Any failure is an error naming the specific reason. None of them degrade to "load it anyway".

use serde::{Deserialize, Serialize};
use thiserror::Error;

use flint_verify::{SignedBlobVerifier, VerifyError};

use super::Genome;
use crate::transport::wasm::ModuleVerifier;

/// Artifact magic ("spark bundle") — namespaces bundles within flint's generic signed-blob format,
/// so a module artifact can never be mistaken for a bundle or vice versa.
const MAGIC: [u8; 4] = *b"SPKB";

/// Ed25519 signature length.
const SIG_LEN: usize = 64;

/// The envelope schema version this build understands.
///
/// Bumped to 2 when `capabilities` was appended. postcard is positional, so an older decoder cannot
/// safely reinterpret the longer payload — and since no bundle has ever been distributed, there is no
/// v1 artifact in the wild to stay compatible with.
pub const SCHEMA_VERSION: u32 = 2;

/// What a bundle carries. postcard is positional, so the field order below **is** the wire schema:
/// new fields must be appended and [`SCHEMA_VERSION`] bumped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    /// Schema version of this envelope.
    pub bundle_version: u32,
    /// The engine these genomes are addressed to. Must equal the artifact's signed name.
    pub engine: String,
    /// Opening plans, most preferred first. Each entry is a postcard-encoded [`Genome`].
    pub genomes: Vec<Vec<u8>>,
    /// The WebAssembly module implementing `engine`, when the bundle ships one.
    ///
    /// Optional because the two useful cases differ: a *new* transport ships code plus plans, while a
    /// re-tuning of an existing transport ships plans alone — and re-sending a module nobody's client
    /// needs to change is wasted bytes on a network we assume is hostile and slow.
    pub wasm: Option<Vec<u8>>,
    /// Host functions the module may import. `None` grants the full table.
    ///
    /// This is inside the signed payload deliberately: a module's authority is fixed by whoever
    /// signed it and cannot be widened by editing a config file. The host-import table is the entire
    /// sandbox boundary — no WASI, no network — so this is the only lever that gives one module less
    /// authority than another, which is what makes a third-party transport safe to run at all.
    ///
    /// `None` means unrestricted, and is what a first-party bundle can reasonably use; a
    /// less-trusted signer should be held to a list. Naming a capability the host does not have is
    /// not an error here — the module simply fails to instantiate if it actually imports it.
    pub capabilities: Option<Vec<String>>,
}

impl Bundle {
    /// A bundle of `genomes` for `engine`, optionally carrying the module that realizes them.
    /// Unrestricted; use [`with_capabilities`](Self::with_capabilities) to scope the module.
    pub fn new(engine: impl Into<String>, genomes: Vec<Vec<u8>>, wasm: Option<Vec<u8>>) -> Self {
        Self {
            bundle_version: SCHEMA_VERSION,
            engine: engine.into(),
            genomes,
            wasm,
            capabilities: None,
        }
    }

    /// Restrict the module to these host imports.
    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    /// postcard-encode the bundle (the form a signature covers).
    pub fn encode(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_stdvec(self)
    }
}

/// Why a bundle was refused. Each variant is a distinct, nameable reason — a bundle never partially
/// loads, and nothing here falls back to accepting it.
#[derive(Debug, Error)]
pub enum BundleError {
    /// Signature, magic, framing, or the bundle-level anti-rollback floor.
    #[error("bundle signature/framing: {0}")]
    Verify(#[from] VerifyError),
    /// The authenticated payload is not a decodable bundle envelope.
    #[error("decode bundle envelope: {0}")]
    Decode(postcard::Error),
    /// Envelope schema mismatch.
    #[error("bundle schema version {got} is not the {want} this build understands")]
    Schema { got: u32, want: u32 },
    /// The bundle names an engine other than the one it was signed as.
    #[error("bundle declares engine `{declared}` but was signed as `{signed}`")]
    EngineMismatch { declared: String, signed: String },
    /// A bundle with no plans has nothing to deliver.
    #[error("bundle carries no genomes")]
    Empty,
    /// A genome inside the bundle is not decodable.
    #[error("genome #{index} is undecodable: {source}")]
    GenomeDecode {
        index: usize,
        source: postcard::Error,
    },
    /// A genome inside the bundle uses an unknown envelope schema.
    #[error("genome #{index} has schema version {got}, not {want}")]
    GenomeSchema { index: usize, got: u32, want: u32 },
    /// A genome addressed to a different engine than the bundle's.
    #[error("genome #{index} is addressed to engine `{engine}`, not `{expected}`")]
    GenomeEngine {
        index: usize,
        engine: String,
        expected: String,
    },
    /// A correctly signed but stale genome — a replay of a plan we have already moved past.
    #[error("genome #{index} version {version} is below the floor {floor}")]
    GenomeRollback {
        index: usize,
        version: u64,
        floor: u64,
    },
}

/// A bundle that passed every check, with its genomes decoded.
#[derive(Debug)]
pub struct VerifiedBundle {
    /// The authenticated name the bundle was signed as — also its engine.
    pub engine: String,
    /// The authenticated, monotonic bundle version.
    pub version: u32,
    /// The decoded, vetted opening plans, in the order the bundle listed them.
    pub genomes: Vec<Genome>,
    /// The module bytes, if the bundle carried them. Still to be compiled by the caller.
    pub wasm: Option<Vec<u8>>,
    /// The authenticated host-import allow-list for the module, or `None` for unrestricted.
    pub capabilities: Option<Vec<String>>,
}

impl VerifiedBundle {
    /// The highest genome version in this bundle.
    ///
    /// The caller persists this as its new genome floor, which is what makes the anti-rollback
    /// monotonic across restarts rather than only within one process.
    pub fn max_genome_version(&self) -> u64 {
        self.genomes.iter().map(|g| g.version).max().unwrap_or(0)
    }
}

/// Verifies delivered transport bundles against an Ed25519 public key.
///
/// Mirrors [`ModuleVerifier`] deliberately, including [`pinned`](Self::pinned) as the production
/// path, so there is one story for "what this build trusts" rather than two.
pub struct BundleVerifier {
    public_key: [u8; 32],
}

impl BundleVerifier {
    /// A verifier for an explicit Ed25519 public key (tests, tooling).
    pub fn new(public_key: [u8; 32]) -> Self {
        Self { public_key }
    }

    /// A verifier using the same key pinned into this binary for modules — the production path.
    pub fn pinned() -> Self {
        Self::new(ModuleVerifier::pinned().key())
    }

    /// Authenticate and vet a bundle artifact.
    ///
    /// `min_bundle_version` is the bundle-level anti-rollback floor; `min_genome_version` is the floor
    /// every carried genome must clear. They are separate because they advance independently: a bundle
    /// can be re-issued (new bundle version) carrying plans that are deliberately unchanged, and a
    /// single bundle can carry plans of differing ages.
    pub fn verify(
        &self,
        artifact: &[u8],
        min_bundle_version: u32,
        min_genome_version: u64,
    ) -> Result<VerifiedBundle, BundleError> {
        // 1 + 2. Signature over the whole payload and the monotonic bundle floor, both before any
        // field below is parsed — so the length-prefixed framing is authenticated before it is acted on.
        let blob =
            SignedBlobVerifier::new(self.public_key, MAGIC).verify(artifact, min_bundle_version)?;
        let bundle: Bundle = postcard::from_bytes(blob.payload).map_err(BundleError::Decode)?;

        // 3. Positional encoding: an unknown schema cannot be safely reinterpreted.
        if bundle.bundle_version != SCHEMA_VERSION {
            return Err(BundleError::Schema {
                got: bundle.bundle_version,
                want: SCHEMA_VERSION,
            });
        }
        // 4. The engine must be the signed name. Without this, a signature for engine A would also
        //    authorize plans for engine B — and the whole point of naming engines (ADR 0013 §7 step 1)
        //    is that the name decides which code interprets the opaque params.
        if bundle.engine != blob.name {
            return Err(BundleError::EngineMismatch {
                declared: bundle.engine,
                signed: blob.name.to_owned(),
            });
        }
        if bundle.genomes.is_empty() {
            return Err(BundleError::Empty);
        }

        // 5. Every genome, individually. One bad plan refuses the whole bundle rather than silently
        //    delivering the subset that happened to parse.
        let mut genomes = Vec::with_capacity(bundle.genomes.len());
        for (index, raw) in bundle.genomes.iter().enumerate() {
            let genome = Genome::decode(raw)
                .map_err(|source| BundleError::GenomeDecode { index, source })?;
            if genome.genome_version != Genome::SCHEMA_VERSION {
                return Err(BundleError::GenomeSchema {
                    index,
                    got: genome.genome_version,
                    want: Genome::SCHEMA_VERSION,
                });
            }
            if genome.engine != bundle.engine {
                return Err(BundleError::GenomeEngine {
                    index,
                    engine: genome.engine,
                    expected: bundle.engine,
                });
            }
            if genome.version < min_genome_version {
                return Err(BundleError::GenomeRollback {
                    index,
                    version: genome.version,
                    floor: min_genome_version,
                });
            }
            genomes.push(genome);
        }

        Ok(VerifiedBundle {
            engine: bundle.engine,
            version: blob.version,
            genomes,
            wasm: bundle.wasm,
            capabilities: bundle.capabilities,
        })
    }
}

/// The bytes a bundle signature must cover: `MAGIC || version || name || postcard(bundle)`.
///
/// Signing itself happens in trusted tooling that holds the private key; this only assembles.
pub fn signing_payload(name: &str, version: u32, bundle: &Bundle) -> Result<Vec<u8>, BundleError> {
    let encoded = bundle.encode().map_err(BundleError::Decode)?;
    Ok(flint_verify::signing_payload(
        &MAGIC, name, version, &encoded,
    ))
}

/// Assemble a complete signed bundle artifact. `signature` must be the detached Ed25519 signature
/// over [`signing_payload`] for the same `name`, `version`, and `bundle`.
pub fn build_artifact(
    name: &str,
    version: u32,
    bundle: &Bundle,
    signature: &[u8; SIG_LEN],
) -> Result<Vec<u8>, BundleError> {
    let encoded = bundle.encode().map_err(BundleError::Decode)?;
    Ok(flint_verify::build_artifact(
        &MAGIC, name, version, &encoded, signature,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::wasm::testutil::dev_keypair;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    const ENGINE: &str = "bip324";

    fn genome(engine: &str, version: u64) -> Vec<u8> {
        let mut g = Genome::new("plan", engine, Default::default(), vec![1, 2, 3]);
        g.version = version;
        g.encode().expect("encode genome")
    }

    fn pubkey(kp: &Ed25519KeyPair) -> [u8; 32] {
        let mut k = [0u8; 32];
        k.copy_from_slice(kp.public_key().as_ref());
        k
    }

    /// Sign a bundle as `name`/`version` with `kp`.
    fn artifact(kp: &Ed25519KeyPair, name: &str, version: u32, bundle: &Bundle) -> Vec<u8> {
        let payload = signing_payload(name, version, bundle).expect("payload");
        let sig = kp.sign(&payload);
        let mut s = [0u8; SIG_LEN];
        s.copy_from_slice(sig.as_ref());
        build_artifact(name, version, bundle, &s).expect("artifact")
    }

    fn verifier(kp: &Ed25519KeyPair) -> BundleVerifier {
        BundleVerifier::new(pubkey(kp))
    }

    #[test]
    fn a_signed_bundle_verifies_and_yields_its_genomes() {
        let kp = dev_keypair();
        let bundle = Bundle::new(
            ENGINE,
            vec![genome(ENGINE, 7), genome(ENGINE, 9)],
            Some(vec![0, 97, 115, 109]), // a wasm preamble stands in; compiling is the caller's job
        );
        let v = verifier(&kp)
            .verify(&artifact(&kp, ENGINE, 3, &bundle), 0, 0)
            .expect("a correctly signed bundle verifies");
        assert_eq!(v.engine, ENGINE);
        assert_eq!(v.version, 3);
        assert_eq!(v.genomes.len(), 2);
        assert_eq!(v.max_genome_version(), 9, "the caller's new genome floor");
        assert!(v.wasm.is_some());
    }

    #[test]
    fn a_bundle_signed_by_another_key_is_refused() {
        let kp = dev_keypair();
        let bundle = Bundle::new(ENGINE, vec![genome(ENGINE, 1)], None);
        let art = artifact(&kp, ENGINE, 1, &bundle);
        // A different key: same bytes, wrong signer.
        let other = Ed25519KeyPair::from_pkcs8(
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .expect("generate")
                .as_ref(),
        )
        .expect("keypair");
        assert!(
            matches!(
                verifier(&other).verify(&art, 0, 0),
                Err(BundleError::Verify(_))
            ),
            "an unknown signer must be refused"
        );
    }

    #[test]
    fn a_tampered_bundle_is_refused() {
        let kp = dev_keypair();
        let bundle = Bundle::new(ENGINE, vec![genome(ENGINE, 1)], None);
        let mut art = artifact(&kp, ENGINE, 1, &bundle);
        // Flip a byte inside the signed payload (past the magic).
        let i = art.len() / 2;
        art[i] ^= 0xFF;
        assert!(
            matches!(
                verifier(&kp).verify(&art, 0, 0),
                Err(BundleError::Verify(_))
            ),
            "a modified payload must fail the signature check"
        );
    }

    #[test]
    fn an_old_bundle_is_refused_even_though_correctly_signed() {
        let kp = dev_keypair();
        let bundle = Bundle::new(ENGINE, vec![genome(ENGINE, 1)], None);
        let art = artifact(&kp, ENGINE, 3, &bundle);
        assert!(
            matches!(
                verifier(&kp).verify(&art, 5, 0),
                Err(BundleError::Verify(_))
            ),
            "bundle v3 under a floor of v5 is a rollback"
        );
    }

    /// The step-4 headline: `Genome::version` is finally load-bearing. A properly signed bundle whose
    /// plans are older than what we have already accepted is a replay, and must be refused.
    #[test]
    fn a_stale_genome_is_refused_even_in_a_valid_bundle() {
        let kp = dev_keypair();
        let bundle = Bundle::new(ENGINE, vec![genome(ENGINE, 4)], None);
        let art = artifact(&kp, ENGINE, 9, &bundle);

        match verifier(&kp).verify(&art, 0, 6) {
            Err(BundleError::GenomeRollback {
                index,
                version,
                floor,
            }) => {
                assert_eq!((index, version, floor), (0, 4, 6));
            }
            other => panic!("expected a genome rollback, got {other:?}"),
        }
        // The same bundle is fine once the floor is at or below the plan's version.
        assert!(verifier(&kp).verify(&art, 0, 4).is_ok(), "floor == version");
    }

    /// A signature for one engine must not authorize plans for another.
    #[test]
    fn a_bundle_cannot_claim_an_engine_it_was_not_signed_as() {
        let kp = dev_keypair();
        let bundle = Bundle::new(
            "some-other-engine",
            vec![genome("some-other-engine", 1)],
            None,
        );
        // Signed as ENGINE, but declares a different engine inside.
        let art = artifact(&kp, ENGINE, 1, &bundle);
        match verifier(&kp).verify(&art, 0, 0) {
            Err(BundleError::EngineMismatch { declared, signed }) => {
                assert_eq!(
                    (declared.as_str(), signed.as_str()),
                    ("some-other-engine", ENGINE)
                );
            }
            other => panic!("expected an engine mismatch, got {other:?}"),
        }
    }

    /// A genome inside the bundle addressed elsewhere refuses the bundle rather than being skipped.
    #[test]
    fn a_genome_addressed_to_another_engine_refuses_the_bundle() {
        let kp = dev_keypair();
        let bundle = Bundle::new(
            ENGINE,
            vec![genome(ENGINE, 1), genome("elsewhere", 1)],
            None,
        );
        let art = artifact(&kp, ENGINE, 1, &bundle);
        assert!(
            matches!(
                verifier(&kp).verify(&art, 0, 0),
                Err(BundleError::GenomeEngine { index: 1, .. })
            ),
            "the second genome is misaddressed, so the whole bundle is refused"
        );
    }

    #[test]
    fn an_empty_or_wrong_schema_bundle_is_refused() {
        let kp = dev_keypair();
        let empty = Bundle::new(ENGINE, Vec::new(), None);
        assert!(matches!(
            verifier(&kp).verify(&artifact(&kp, ENGINE, 1, &empty), 0, 0),
            Err(BundleError::Empty)
        ));

        let mut future = Bundle::new(ENGINE, vec![genome(ENGINE, 1)], None);
        future.bundle_version = SCHEMA_VERSION + 1;
        assert!(matches!(
            verifier(&kp).verify(&artifact(&kp, ENGINE, 1, &future), 0, 0),
            Err(BundleError::Schema { .. })
        ));
    }

    /// Capabilities travel inside the signature, so they survive verification intact and a tampered
    /// grant fails the signature rather than widening the module's authority.
    #[test]
    fn the_capability_grant_is_authenticated() {
        let kp = dev_keypair();
        let caps = vec!["host_rand".to_owned(), "host_hash".to_owned()];
        let bundle = Bundle::new(ENGINE, vec![genome(ENGINE, 1)], Some(vec![0, 97, 115, 109]))
            .with_capabilities(caps.clone());
        let art = artifact(&kp, ENGINE, 1, &bundle);

        let v = verifier(&kp).verify(&art, 0, 0).expect("verifies");
        assert_eq!(
            v.capabilities,
            Some(caps),
            "the grant survives verification"
        );

        // An unrestricted bundle stays unrestricted — `None` is distinct from an empty list.
        let open = Bundle::new(ENGINE, vec![genome(ENGINE, 1)], None);
        let v = verifier(&kp)
            .verify(&artifact(&kp, ENGINE, 1, &open), 0, 0)
            .expect("verifies");
        assert_eq!(v.capabilities, None);

        // An empty grant is a real restriction and must round-trip as one, not collapse to None.
        let closed =
            Bundle::new(ENGINE, vec![genome(ENGINE, 1)], None).with_capabilities(Vec::new());
        let v = verifier(&kp)
            .verify(&artifact(&kp, ENGINE, 1, &closed), 0, 0)
            .expect("verifies");
        assert_eq!(v.capabilities, Some(Vec::new()), "empty grants nothing");
    }

    /// A module artifact must not verify as a bundle: the magic namespaces them apart.
    #[test]
    fn a_module_artifact_is_not_a_bundle() {
        let kp = dev_keypair();
        let wasm = wat::parse_str(crate::transport::wasm::testutil::XOR_WAT).expect("assemble");
        let sig = kp.sign(&crate::transport::wasm::signing_payload("obfs", 1, &wasm));
        let mut s = [0u8; SIG_LEN];
        s.copy_from_slice(sig.as_ref());
        let module_artifact = crate::transport::wasm::build_artifact("obfs", 1, &wasm, &s);
        assert!(
            matches!(
                verifier(&kp).verify(&module_artifact, 0, 0),
                Err(BundleError::Verify(_))
            ),
            "SPKW must not pass as SPKB"
        );
    }
}
