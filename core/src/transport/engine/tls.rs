//! The TLS engine: the boring/flint-tls Chrome realization behind the [`OpeningEngine`] seam
//! (ADR 0013 §7 step 1). Owns every TLS type that used to leak into the core — it decodes the
//! opaque [`OpeningPlan`] params as a postcard `Gambit` and gates them through `Profile::for_boring`.

use std::io;

use async_trait::async_trait;
use flint_tls::gambit::Gambit;
use flint_tls::Profile;

use super::{EngineId, OpeningEngine, OpeningPlan};
use crate::BoxedStream;

/// The TLS engine (ZST). Registered under [`super::TLS`].
pub struct TlsEngine;

/// The shared static instance the registry hands out.
pub static ENGINE: &TlsEngine = &TlsEngine;

impl TlsEngine {
    /// Per-connection context bytes for a `compute_gambit` module: the host-controlled wall clock,
    /// the one fact a sandboxed module can't self-source.
    #[cfg(feature = "wasm-transport")]
    pub fn context_bytes(unix_secs: u64) -> Vec<u8> {
        flint_tls::gambit::GambitContext { unix_secs }.encode()
    }

    /// Decode opaque params into a boring [`Profile`], gating `requires` via `Profile::for_boring`.
    /// `None` on empty / undecodable / declined params — the caller then falls back (connectivity
    /// must never depend on a dynamic plan succeeding). `warn` narrates the attempt (undecodable /
    /// declined / unrealizable knobs); pass `false` for the static fallback, whose knobs are already
    /// surfaced once at transport construction, to avoid per-connection log spam.
    fn resolve(params: &[u8], warn: bool) -> Option<Profile> {
        if params.is_empty() {
            return None;
        }
        let gambit = match postcard::from_bytes::<Gambit>(params) {
            Ok(g) => g,
            Err(e) => {
                if warn {
                    tracing::warn!(error = %e, "computed gambit undecodable; using fallback");
                }
                return None;
            }
        };
        match Profile::for_boring(&gambit) {
            Ok(resolved) => {
                if warn {
                    for note in &resolved.unrealizable {
                        tracing::warn!(knob = note, "computed gambit knob not realizable on boring");
                    }
                }
                Some(resolved.profile)
            }
            Err(e) => {
                if warn {
                    tracing::warn!(error = %e, "computed gambit declined by boring; using fallback");
                }
                None
            }
        }
    }
}

#[async_trait]
impl OpeningEngine for TlsEngine {
    fn id(&self) -> EngineId {
        super::TLS
    }

    async fn realize(&self, stream: BoxedStream, plan: &OpeningPlan) -> io::Result<BoxedStream> {
        // Prefer the dynamic params (narrated per-computation); else the static fallback (resolved
        // quietly — its knobs were already logged at construction). If neither realizes, degrade to
        // the Chrome anchor but say so loudly, so an empty/invalid fallback surfaces as a bug rather
        // than silently masking the configured profile.
        let profile = match Self::resolve(&plan.params, true) {
            Some(p) => p,
            None => Self::resolve(&plan.fallback, false).unwrap_or_else(|| {
                tracing::warn!(
                    "no realizable opening plan (params and fallback both declined); \
                     using the default Chrome profile"
                );
                Profile::default()
            }),
        };
        let tls = flint_tls::connect(stream, &plan.sni, &profile).await?;
        Ok(Box::new(tls))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flint_tls::gambit::{ClientHello, EchMode, Records};

    fn blob(clienthello: ClientHello, records: Records) -> Vec<u8> {
        postcard::to_stdvec(&Gambit {
            genome_version: 1,
            version: 1,
            id: "static".into(),
            anchor: Default::default(),
            clienthello,
            records,
            wire: Default::default(),
            requires: Vec::new(),
        })
        .unwrap()
    }

    #[test]
    fn resolve_matches_the_direct_profile_resolve() {
        // The engine's decode + for_boring path must produce the exact `Profile` the old direct
        // `Profile::resolve(clienthello, records)` produced — i.e. a byte-identical handshake.
        let cases = [
            (ClientHello::default(), Records::default()),
            (
                ClientHello {
                    ech: Some(EchMode::Off),
                    pq_kem: Some(false),
                    ..Default::default()
                },
                Records {
                    size_limit: Some(1300),
                    ..Default::default()
                },
            ),
        ];
        for (ch, rec) in cases {
            let want = Profile::resolve(&ch, &rec).profile;
            let got = TlsEngine::resolve(&blob(ch, rec), false).expect("static params resolve");
            assert_eq!(got, want);
        }
    }

    #[test]
    fn empty_and_undecodable_params_decline() {
        assert!(TlsEngine::resolve(&[], true).is_none());
        assert!(TlsEngine::resolve(&[0xFF], true).is_none());
    }
}
