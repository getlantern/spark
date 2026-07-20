//! The discovery harness — *inner loop* (ADR 0006 P5, design §5).
//!
//! The full search loop is **server-side** (§5.5): the servers are the sensors, fitness is the
//! arrival rate of successful connections, and only signed genome assignments cross to clients. What
//! lives here is the **inner tier** (§5.2) — the *cheap, fast, no-censor-contact* pre-filter that
//! spark can run because it owns the boring engine: generate candidate genomes (GA mutation +
//! crossover, §5.1), **realize** each through boring into an actual ClientHello, and score its
//! **fidelity to the anchor** via JA4 + structural distance. This guards the `fidelity_floor` term of
//! the composite fitness so a genome can't win by becoming a glaring anomaly — it does *not* decide
//! evasion (that's the outer/server loop's arrival signal).
//!
//! Note: for **constrained** genomes the fidelity signal is intentionally coarse — boring keeps them
//! Chrome-faithful by construction, so only knobs that change the *extension set* (ECH, ALPS,
//! record_size_limit) move the JA4. The scorer earns its keep on the **unconstrained** (P4) regime,
//! where a module emits arbitrary ClientHello bytes and fidelity can vary widely.
//!
//! The GA operators are **protocol-neutral** (ADR 0013 §4 item 7): they evolve the neutral
//! [`Genome`]'s wire-shaping plan directly and delegate protocol-specific `engine_params` evolution to
//! a per-engine [`EngineDiscovery`] hook. They stay pure and deterministic given a seed (reproducible
//! search + auditability, §5.5). The realize/score half (JA4 fidelity) is TLS-specific and lives
//! behind the `anytls` feature with the [`TlsDiscovery`] hook.

use super::engine::Genome;

/// A small, seedable PRNG (SplitMix64) — dependency-free and **deterministic** so a search run (and
/// its tests) reproduce exactly from a seed. Not cryptographic; only steers mutation choices.
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Seed the generator. The same seed always yields the same sequence.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..n` (`n` must be non-zero).
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

/// Per-engine genetic operators over the opaque `engine_params` (ADR 0013 §4 item 7). The generic GA
/// evolves the neutral [`Genome`]'s wire plan; protocol-specific param evolution is delegated here —
/// the engine owns any internal sub-layer structure (for TLS, the ClientHello / records knobs).
pub trait EngineDiscovery {
    /// Perturb one protocol-specific knob of `params`. Returns `params` unchanged if it can't decode.
    fn mutate_params(&self, params: &[u8], rng: &mut SplitMix64) -> Vec<u8>;
    /// Recombine two parents' params. Returns one parent's bytes if either can't decode.
    fn crossover_params(&self, a: &[u8], b: &[u8], rng: &mut SplitMix64) -> Vec<u8>;
}

/// Perturb exactly one knob of `g` (GA mutation, §5.1): a generic Layer-C wire knob, or — via the
/// engine hook — a protocol-specific param knob. Returns a new genome; the input is unchanged.
pub fn mutate<D: EngineDiscovery>(g: &Genome, rng: &mut SplitMix64, engine: &D) -> Genome {
    let mut m = g.clone();
    // Two engine-neutral wire arms; everything protocol-specific is delegated to the engine hook.
    match rng.below(4) {
        0 => {
            m.wire.segment_split = match rng.below(3) {
                0 => "none".to_string(),
                1 => "sni_boundary".to_string(),
                _ => format!("{}", 1 + rng.below(20)),
            }
        }
        1 => {
            m.wire.delay_ms = if rng.coin() {
                Some(rng.below(30))
            } else {
                None
            }
        }
        _ => m.engine_params = engine.mutate_params(&m.engine_params, rng),
    }
    m
}

/// Recombine two genomes (GA crossover, §5.1): the generic `wire` layer is taken from one parent, and
/// `engine_params` recombination is delegated to the engine hook. Header (`id`/`engine`/versions)
/// follows parent `a`.
pub fn crossover<D: EngineDiscovery>(
    a: &Genome,
    b: &Genome,
    rng: &mut SplitMix64,
    engine: &D,
) -> Genome {
    Genome {
        genome_version: a.genome_version,
        version: a.version,
        id: a.id.clone(),
        engine: a.engine.clone(),
        wire: if rng.coin() {
            a.wire.clone()
        } else {
            b.wire.clone()
        },
        engine_params: engine.crossover_params(&a.engine_params, &b.engine_params, rng),
    }
}

/// Generate a population of `size` candidates from `seed`: the seed itself, then mutants (and
/// crossovers once there are two parents). Deterministic given `rng`.
pub fn generate_population<D: EngineDiscovery>(
    seed: &Genome,
    size: usize,
    rng: &mut SplitMix64,
    engine: &D,
) -> Vec<Genome> {
    let mut pop = Vec::with_capacity(size.max(1));
    pop.push(seed.clone());
    while pop.len() < size {
        let parent = pop[rng.below(pop.len() as u64) as usize].clone();
        let child = if pop.len() >= 2 && rng.coin() {
            let other = pop[rng.below(pop.len() as u64) as usize].clone();
            crossover(&parent, &other, rng, engine)
        } else {
            mutate(&parent, rng, engine)
        };
        pop.push(child);
    }
    pop
}

#[cfg(feature = "anytls")]
pub use realize::{run_inner_loop, Fidelity, Scored, TlsDiscovery};

/// The realize-and-score half of the inner loop + the TLS engine's discovery hook — both need the
/// boring engine (and TLS types), so they're behind `anytls`.
#[cfg(feature = "anytls")]
mod realize {
    use super::*;
    use flint_tls::anchor::capture_client_hello;
    use flint_tls::gambit::{EchMode, Gambit, Perm};
    use flint_tls::ja4::{ja4, parse_client_hello, ClientHelloSummary};
    use flint_tls::Profile;
    use std::collections::BTreeSet;

    /// The TLS engine's discovery hook (ADR 0013 §4 item 7). The opaque `engine_params` are a postcard
    /// `Gambit`, so param evolution decodes it, perturbs one ClientHello/records knob, and re-encodes.
    pub struct TlsDiscovery;

    impl EngineDiscovery for TlsDiscovery {
        fn mutate_params(&self, params: &[u8], rng: &mut SplitMix64) -> Vec<u8> {
            let mut g = match postcard::from_bytes::<Gambit>(params) {
                Ok(g) => g,
                Err(_) => {
                    tracing::warn!("TlsDiscovery: undecodable engine_params; left unchanged");
                    return params.to_vec();
                }
            };
            match rng.below(7) {
                0 => {
                    // ECH mode cycle.
                    g.clienthello.ech = Some(match g.clienthello.ech {
                        None | Some(EchMode::Grease) => EchMode::Off,
                        Some(EchMode::Off) => EchMode::Real,
                        Some(EchMode::Real) => EchMode::Grease,
                    });
                }
                1 => g.clienthello.alps = Some(!g.clienthello.alps.unwrap_or(true)),
                2 => g.clienthello.pq_kem = Some(!g.clienthello.pq_kem.unwrap_or(true)),
                3 => g.clienthello.grease_seed = Some(rng.next_u64() as u32),
                4 => g.clienthello.extension_order = Some(Perm::PermuteSeed(rng.next_u64() as u32)),
                5 => {
                    g.clienthello.padding_target = if rng.coin() {
                        Some(256 + rng.below(768) as u16)
                    } else {
                        None
                    }
                }
                _ => {
                    g.records.size_limit = if rng.coin() {
                        Some(512 + rng.below(3585) as u16)
                    } else {
                        None
                    }
                }
            }
            postcard::to_stdvec(&g).unwrap_or_else(|_| params.to_vec())
        }

        fn crossover_params(&self, a: &[u8], b: &[u8], rng: &mut SplitMix64) -> Vec<u8> {
            let (ga, gb) = match (
                postcard::from_bytes::<Gambit>(a),
                postcard::from_bytes::<Gambit>(b),
            ) {
                (Ok(ga), Ok(gb)) => (ga, gb),
                _ => return a.to_vec(),
            };
            // Each TLS layer (A = ClientHello, B = records) taken independently; default to parent a.
            let mut child = ga.clone();
            if rng.coin() {
                child.clienthello = gb.clienthello;
            }
            if rng.coin() {
                child.records = gb.records;
            }
            postcard::to_stdvec(&child).unwrap_or_else(|_| a.to_vec())
        }
    }

    /// RFC 8701 GREASE check, mirroring `flint_tls::ja4`'s internal filter (not public): a
    /// GREASE-reserved 16-bit value has both bytes equal and of the form `0x?a`.
    fn is_grease(v: u16) -> bool {
        (v >> 8) as u8 == (v & 0xff) as u8 && (v & 0x0f) == 0x0a
    }

    /// A candidate's fidelity to the anchor, from realizing it through boring.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Fidelity {
        /// `false` if boring declined the genome (capability gate) or the ClientHello didn't parse.
        pub realized: bool,
        /// The realized ClientHello's JA4, if realized.
        pub ja4: Option<String>,
        /// Whether that JA4 equals the anchor's (the binary fidelity gate).
        pub matches_anchor: bool,
        /// Structural distance from the anchor's ClientHello (lower = more faithful): the symmetric
        /// difference of GREASE-stripped cipher + extension sets, plus ALPN and version mismatches.
        pub distance: u32,
    }

    /// A scored candidate, ready for ranking / the outer-loop field trial.
    #[derive(Debug, Clone)]
    pub struct Scored {
        pub genome: Genome,
        pub fidelity: Fidelity,
    }

    fn nongrease_set(values: &[u16]) -> BTreeSet<u16> {
        values.iter().copied().filter(|v| !is_grease(*v)).collect()
    }

    fn highest_version(s: &ClientHelloSummary) -> u16 {
        s.supported_versions
            .as_ref()
            .and_then(|v| v.iter().copied().filter(|x| !is_grease(*x)).max())
            .unwrap_or(s.legacy_version)
    }

    /// Structural distance between two ClientHellos (symmetric set differences + ALPN/version).
    fn distance(a: &ClientHelloSummary, b: &ClientHelloSummary) -> u32 {
        let ciph = nongrease_set(&a.ciphers)
            .symmetric_difference(&nongrease_set(&b.ciphers))
            .count() as u32;
        let ext = nongrease_set(&a.extensions)
            .symmetric_difference(&nongrease_set(&b.extensions))
            .count() as u32;
        let alpn = (a.alpn_first != b.alpn_first) as u32;
        let ver = (highest_version(a) != highest_version(b)) as u32;
        ciph + ext + alpn + ver
    }

    /// Realize `g` through boring (the constrained executor) and parse the emitted ClientHello.
    /// `None` if the genome isn't decodable as a TLS gambit, boring declines it, or no ClientHello is
    /// produced.
    async fn realize_summary(g: &Genome, sni: &str) -> Option<ClientHelloSummary> {
        let gambit = postcard::from_bytes::<Gambit>(&g.engine_params).ok()?;
        let resolved = Profile::for_boring(&gambit).ok()?;
        let ch = capture_client_hello(&resolved.profile, sni).await.ok()?;
        parse_client_hello(&ch)
    }

    /// Score one candidate against a pre-captured anchor summary + its JA4.
    async fn score(
        g: &Genome,
        anchor: &ClientHelloSummary,
        anchor_ja4: &str,
        sni: &str,
    ) -> Fidelity {
        match realize_summary(g, sni).await {
            Some(summary) => {
                let candidate_ja4 = ja4(&summary);
                Fidelity {
                    realized: true,
                    matches_anchor: candidate_ja4 == anchor_ja4,
                    ja4: Some(candidate_ja4),
                    distance: distance(&summary, anchor),
                }
            }
            None => Fidelity {
                realized: false,
                ja4: None,
                matches_anchor: false,
                distance: u32::MAX,
            },
        }
    }

    /// Run the inner loop: from `seed`, evolve over `generations`, each generation generating a
    /// `pop_size` population (mutation + crossover via the [`TlsDiscovery`] hook), realizing + scoring
    /// every candidate's fidelity, and selecting the fittest (lowest distance) **distinct-JA4**
    /// survivors as the next generation's parents (novelty pressure, §5.1 — so the population doesn't
    /// collapse onto one fingerprint). Returns the final population, ranked most-faithful first.
    ///
    /// This is the cheap, no-censor pre-filter: its output is a fidelity-ranked, diverse candidate set
    /// for the server-side outer loop to field-trial — it does not itself judge evasion.
    pub async fn run_inner_loop(
        seed: &Genome,
        pop_size: usize,
        generations: usize,
        rng_seed: u64,
        sni: &str,
    ) -> Vec<Scored> {
        let mut rng = SplitMix64::new(rng_seed);
        // The reference is always the Chrome-137 anchor (boring's default profile), independent of the
        // seed — a deviating seed is scored against genuine Chrome, not against itself.
        let anchor = match capture_client_hello(&Profile::default(), sni)
            .await
            .ok()
            .as_deref()
            .and_then(parse_client_hello)
        {
            Some(s) => s,
            None => return Vec::new(),
        };
        let anchor_ja4 = ja4(&anchor);

        let mut parents = vec![seed.clone()];
        let mut ranked: Vec<Scored> = Vec::new();
        for _ in 0..generations.max(1) {
            // Build a population seeded from the current parents.
            let mut pop = Vec::with_capacity(pop_size.max(1));
            pop.extend(parents.iter().cloned());
            while pop.len() < pop_size {
                let a = pop[rng.below(pop.len() as u64) as usize].clone();
                let child = if pop.len() >= 2 && rng.coin() {
                    let b = pop[rng.below(pop.len() as u64) as usize].clone();
                    crossover(&a, &b, &mut rng, &TlsDiscovery)
                } else {
                    mutate(&a, &mut rng, &TlsDiscovery)
                };
                pop.push(child);
            }
            // Score every candidate.
            let mut scored = Vec::with_capacity(pop.len());
            for g in pop {
                let fidelity = score(&g, &anchor, &anchor_ja4, sni).await;
                scored.push(Scored {
                    genome: g,
                    fidelity,
                });
            }
            // Rank: realized first, then lowest distance.
            scored.sort_by(|x, y| {
                y.fidelity
                    .realized
                    .cmp(&x.fidelity.realized)
                    .then(x.fidelity.distance.cmp(&y.fidelity.distance))
            });
            // Novelty: keep the best survivor per distinct JA4 as the next parents.
            let mut seen = BTreeSet::new();
            parents = scored
                .iter()
                .filter(|s| s.fidelity.realized)
                .filter(|s| seen.insert(s.fidelity.ja4.clone()))
                .take(pop_size.max(1))
                .map(|s| s.genome.clone())
                .collect();
            ranked = scored;
            if parents.is_empty() {
                break;
            }
        }
        ranked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trivial protocol-blind hook for the generic GA tests: perturbs the opaque bytes without any
    /// engine knowledge, proving the generic (wire) GA is engine-neutral and runs without boring.
    struct FlipByte;

    impl EngineDiscovery for FlipByte {
        fn mutate_params(&self, params: &[u8], _rng: &mut SplitMix64) -> Vec<u8> {
            let mut p = params.to_vec();
            match p.first_mut() {
                Some(b) => *b ^= 1,
                None => p.push(1),
            }
            p
        }
        fn crossover_params(&self, a: &[u8], _b: &[u8], _rng: &mut SplitMix64) -> Vec<u8> {
            a.to_vec()
        }
    }

    fn seed() -> Genome {
        Genome::new(
            "seed",
            super::super::engine::TLS,
            Default::default(),
            vec![0u8; 4],
        )
    }

    #[test]
    fn splitmix_is_deterministic() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn mutate_is_reproducible_and_changes_the_genome() {
        let s = seed();
        let m1 = mutate(&s, &mut SplitMix64::new(7), &FlipByte);
        let m2 = mutate(&s, &mut SplitMix64::new(7), &FlipByte);
        assert_eq!(m1, m2, "same seed → same mutation");
        // Over a spread of seeds, a mutation must actually change something.
        let changed = (0..32).any(|k| mutate(&s, &mut SplitMix64::new(k), &FlipByte) != s);
        assert!(changed, "mutation should alter the genome");
    }

    #[test]
    fn crossover_uses_generic_wire_and_delegates_params() {
        let mut a = seed();
        a.wire.segment_split = "sni_boundary".into();
        a.engine_params = vec![0xAA];
        let mut b = seed();
        b.wire.segment_split = "none".into();
        b.engine_params = vec![0xBB];
        for k in 0..16 {
            let c = crossover(&a, &b, &mut SplitMix64::new(k), &FlipByte);
            assert!(c.wire == a.wire || c.wire == b.wire, "wire from one parent");
            assert_eq!(
                c.engine_params, a.engine_params,
                "FlipByte crossover delegates to parent a's params"
            );
        }
    }

    #[test]
    fn generate_population_is_sized_and_reproducible() {
        let s = seed();
        let p1 = generate_population(&s, 12, &mut SplitMix64::new(99), &FlipByte);
        let p2 = generate_population(&s, 12, &mut SplitMix64::new(99), &FlipByte);
        assert_eq!(p1.len(), 12);
        assert_eq!(p1, p2);
        assert_eq!(p1[0], s, "the seed leads the population");
    }
}

#[cfg(all(test, feature = "anytls"))]
mod realize_tests {
    use super::*;
    use flint_tls::anchor::ANCHOR_JA4;
    use flint_tls::gambit::{ClientHello, Gambit, Records, Wire};

    /// A neutral genome for the `tls` engine wrapping `clienthello` (records/wire default).
    fn tls_seed(clienthello: ClientHello) -> Genome {
        let gambit = Gambit {
            genome_version: 1,
            version: 1,
            id: "seed".into(),
            anchor: Default::default(),
            clienthello,
            records: Records::default(),
            wire: Wire::default(),
            requires: Vec::new(),
        };
        Genome::new(
            "seed",
            super::super::engine::TLS,
            Default::default(),
            postcard::to_stdvec(&gambit).expect("encode gambit"),
        )
    }

    #[tokio::test]
    async fn the_seed_realizes_to_the_anchor() {
        // An empty genome → boring's default profile → the anchor ClientHello: distance 0, matches.
        let ranked =
            run_inner_loop(&tls_seed(ClientHello::default()), 1, 1, 1, "example.com").await;
        assert_eq!(ranked.len(), 1);
        let f = &ranked[0].fidelity;
        assert!(f.realized);
        assert!(f.matches_anchor);
        assert_eq!(f.distance, 0);
        assert_eq!(f.ja4.as_deref(), Some(ANCHOR_JA4));
    }

    #[tokio::test]
    async fn dropping_alps_lowers_fidelity() {
        // ALPS off removes the application_settings extension → a different JA4, nonzero distance.
        let seed = tls_seed(ClientHello {
            alps: Some(false),
            ..Default::default()
        });
        let ranked = run_inner_loop(&seed, 1, 1, 1, "example.com").await;
        let f = &ranked[0].fidelity;
        assert!(f.realized);
        assert!(
            !f.matches_anchor,
            "an ALPS-off profile must not match the anchor JA4"
        );
        assert!(f.distance >= 1);
    }

    #[tokio::test]
    async fn loop_ranks_most_faithful_first_and_stays_diverse() {
        let ranked =
            run_inner_loop(&tls_seed(ClientHello::default()), 10, 2, 123, "example.com").await;
        assert!(!ranked.is_empty());
        // Sorted: realized-first, then non-decreasing distance.
        for w in ranked.windows(2) {
            if w[0].fidelity.realized && w[1].fidelity.realized {
                assert!(w[0].fidelity.distance <= w[1].fidelity.distance);
            }
        }
        // The seed (anchor) is maximally faithful, so the top candidate matches the anchor.
        assert!(ranked[0].fidelity.matches_anchor);
        // Novelty: the realized population shows more than one distinct JA4 (didn't collapse).
        let distinct: std::collections::BTreeSet<_> = ranked
            .iter()
            .filter_map(|s| s.fidelity.ja4.clone())
            .collect();
        assert!(
            distinct.len() >= 2,
            "the population should explore >1 fingerprint"
        );
    }
}
