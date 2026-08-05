//! Retry backoff for the loops that poll a Lantern server forever (config refresh, diagnostics
//! upload).
//!
//! Both loops retry indefinitely against shared infrastructure, so their pacing is a fleet-wide
//! property, not a per-client one. Two things follow from that:
//!
//! * **Jitter is mandatory.** Clients that fail together retry together. A deterministic delay keeps
//!   an outage's worth of clients in lockstep for as long as the outage lasts, so every retry lands
//!   as a synchronized spike rather than as spread-out load (Marc Brooker, *Exponential Backoff and
//!   Jitter*, AWS Architecture Blog).
//! * **Time-to-cap, not the cap, sets an outage's cost.** A ramp that takes an hour to saturate
//!   keeps every client in its hot phase for the whole incident.
//!
//! So the delay for consecutive failure `n` is centered on `BASE · 2^(n-1)`, capped at [`CAP`], with
//! the actual sleep drawn uniformly within ±50% of that centre. Jitter is symmetric about the
//! centre so that [`CAP`] keeps its plain meaning — the *mean* steady-state poll interval — rather
//! than silently halving it, which a `[0, cap]` draw would do.
//!
//! Against the previous deterministic `10ms·n²` ramp, per client: 7 requests in the first minute
//! instead of 26, saturation after 9 failures (~4 min) instead of 110 (~75 min), and an unchanged
//! 2-minute mean interval once saturated.
//!
//! ```
//! use spark_core::backoff;
//!
//! // The centre doubles per consecutive failure, then holds at the cap.
//! assert_eq!(backoff::centre(1), std::time::Duration::from_millis(500));
//! assert_eq!(backoff::centre(3), std::time::Duration::from_millis(2_000));
//! assert_eq!(backoff::centre(99), backoff::CAP);
//!
//! // The sleep itself is a jittered draw within ±50% of that centre.
//! let (lo, hi) = backoff::bounds(3);
//! assert!((lo..=hi).contains(&backoff::with_jitter(3)));
//! ```

use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};

/// Centre of the delay after the first failure; doubles per consecutive failure.
pub const BASE: Duration = Duration::from_millis(500);

/// Mean steady-state interval once the ramp saturates, on the 9th consecutive failure.
pub const CAP: Duration = Duration::from_secs(120);

/// The unjittered centre of the delay after `attempt` (1-based) consecutive failures:
/// `BASE · 2^(attempt-1)`, capped at [`CAP`]. Pure, so the growth curve is directly testable;
/// [`with_jitter`] samples around it.
///
/// `attempt` of 0 is treated as 1 — callers count failures from one.
pub fn centre(attempt: u32) -> Duration {
    // Shift width is clamped well below u64's 63-bit limit; the cap makes anything past ~8 moot.
    let doublings = attempt.saturating_sub(1).min(31);
    let ms = (BASE.as_millis() as u64).saturating_mul(1u64 << doublings);
    Duration::from_millis(ms).min(CAP)
}

/// Inclusive `[lo, hi]` range [`with_jitter`] can return for `attempt`: ±50% around [`centre`].
pub fn bounds(attempt: u32) -> (Duration, Duration) {
    let c = centre(attempt);
    (c / 2, c + c / 2)
}

/// How long to sleep after `attempt` (1-based) consecutive failures: a uniform draw from
/// [`bounds`].
///
/// The spread is what decorrelates clients that failed at the same instant; at the cap it scatters
/// them across a two-minute window.
pub fn with_jitter(attempt: u32) -> Duration {
    let mut bytes = [0u8; 8];
    // `SecureRandom` is sealed, so entropy reaches `draw` as a value rather than an injected trait
    // — which also lets the range mapping be tested deterministically.
    let raw = SystemRandom::new()
        .fill(&mut bytes)
        .ok()
        .map(|()| u64::from_le_bytes(bytes));
    let (lo, hi) = bounds(attempt);
    draw(lo, hi, raw)
}

/// Uniform draw from `[lo, hi]` given raw entropy. `None` means the RNG was unavailable, in which
/// case we return `hi` — under the load this function exists to shed, the safe direction to fail is
/// *longer*.
fn draw(lo: Duration, hi: Duration, raw: Option<u64>) -> Duration {
    let (lo_ms, hi_ms) = (lo.as_millis() as u64, hi.as_millis() as u64);
    let (Some(raw), true) = (raw, hi_ms > lo_ms) else {
        return hi;
    };
    // Modulo bias is bounded by span/2^64 — with a span under 2^18 ms it is unmeasurable, and the
    // consumer is a sleep timer, not a key.
    let span = hi_ms - lo_ms + 1;
    Duration::from_millis(lo_ms + raw % span)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn centre_doubles_then_saturates() {
        assert_eq!(centre(1), Duration::from_millis(500));
        assert_eq!(centre(2), Duration::from_millis(1_000));
        assert_eq!(centre(3), Duration::from_millis(2_000));
        assert_eq!(centre(8), Duration::from_millis(64_000));
        // 500ms · 2^8 = 128s, past the 120s cap.
        assert_eq!(centre(9), CAP);
        assert_eq!(centre(10_000), CAP);
    }

    /// `attempt` is 1-based; 0 must not underflow into a huge shift.
    #[test]
    fn centre_treats_zero_as_the_first_attempt() {
        assert_eq!(centre(0), centre(1));
    }

    #[test]
    fn jitter_stays_within_bounds() {
        for attempt in [1u32, 3, 9, 50] {
            let (lo, hi) = bounds(attempt);
            for _ in 0..200 {
                let d = with_jitter(attempt);
                assert!(d >= lo, "attempt {attempt}: {d:?} below {lo:?}");
                assert!(d <= hi, "attempt {attempt}: {d:?} above {hi:?}");
            }
        }
    }

    /// The whole point of the change: clients failing in lockstep must not sleep in lockstep.
    /// A deterministic backoff would make every draw identical.
    #[test]
    fn jitter_actually_varies() {
        let draws: std::collections::HashSet<_> = (0..100).map(|_| with_jitter(9)).collect();
        assert!(
            draws.len() > 50,
            "expected a wide spread at the cap, got {} distinct values",
            draws.len()
        );
    }

    /// Jitter must be symmetric about the centre, so `CAP` stays the *mean* steady-state interval.
    /// An asymmetric draw (e.g. `[0, cap]`) would halve the effective interval during a long
    /// outage — doubling the load the cap was chosen to bound.
    #[test]
    fn jitter_is_centred_so_the_cap_is_the_mean_interval() {
        let (lo, hi) = bounds(9);
        assert_eq!(lo, CAP / 2);
        assert_eq!(hi, CAP + CAP / 2);
        assert_eq!((lo + hi) / 2, CAP);
    }

    /// Time-to-cap is what bounds an outage's request volume, so pin it.
    #[test]
    fn reaches_the_cap_within_nine_failures() {
        assert!(centre(8) < CAP);
        assert_eq!(centre(9), CAP);
        let ramp: Duration = (1..=9).map(centre).sum();
        assert!(ramp < Duration::from_secs(250), "ramp to cap took {ramp:?}");
    }

    /// The early ramp is where an outage's load actually comes from.
    #[test]
    fn issues_far_fewer_requests_in_the_first_minute_than_the_old_quadratic_ramp() {
        let count = |f: &dyn Fn(u32) -> Duration| {
            let (mut elapsed, mut n) = (Duration::ZERO, 0u32);
            while elapsed < Duration::from_secs(60) {
                n += 1;
                elapsed += f(n);
            }
            n
        };
        // The ramp this replaced: 10ms·n², capped at 2 min.
        let old = |n: u32| Duration::from_millis((10 * u64::from(n) * u64::from(n)).min(120_000));
        assert_eq!(count(&old), 26);
        assert!(count(&centre) <= 8, "got {}", count(&centre));
    }

    /// A broken RNG must lengthen the sleep, never shorten it.
    #[test]
    fn failed_rng_falls_back_to_the_upper_bound() {
        let hi = Duration::from_millis(4_000);
        assert_eq!(draw(Duration::from_millis(50), hi, None), hi);
    }

    /// The draw must span the full `[lo, hi]` inclusive range — a mapping that never reaches an
    /// endpoint would quietly narrow the spread jitter exists to create.
    #[test]
    fn draw_covers_both_endpoints() {
        let (lo, hi) = (Duration::from_millis(50), Duration::from_millis(4_000));
        let span = hi.as_millis() as u64 - lo.as_millis() as u64 + 1;
        assert_eq!(draw(lo, hi, Some(0)), lo);
        assert_eq!(draw(lo, hi, Some(span - 1)), hi);
        assert_eq!(draw(lo, hi, Some(span)), lo); // wraps
    }

    #[test]
    fn degenerate_range_returns_the_upper_bound() {
        let lo = Duration::from_millis(50);
        assert_eq!(draw(lo, lo, Some(12_345)), lo);
        // hi below lo must not underflow.
        assert_eq!(
            draw(lo, Duration::from_millis(1), Some(12_345)),
            Duration::from_millis(1)
        );
    }
}
