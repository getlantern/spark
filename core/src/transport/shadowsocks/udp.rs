//! SS-2022 UDP: native packet build/parse + sliding-window replay filter.

// consumed by packet codec (Task 10) + sink/source (Task 11); remove at the final sweep.
#![allow(dead_code)]

/// Size of the replay window (bits behind the highest accepted packet ID).
const WINDOW: u64 = 64;

/// A sliding-window replay filter over u64 packet IDs (SIP022 §3.2.4).
pub struct ReplayWindow {
    highest: u64,
    bitmap: u64, // bit i set => (highest - i) was seen
    seen_any: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        ReplayWindow {
            highest: 0,
            bitmap: 0,
            seen_any: false,
        }
    }

    /// Check `id`: returns true if it is fresh (and records it), false if duplicate/out-of-window.
    pub fn accept(&mut self, id: u64) -> bool {
        if !self.seen_any {
            self.seen_any = true;
            self.highest = id;
            self.bitmap = 1; // bit 0 = highest seen
            return true;
        }
        if id > self.highest {
            let shift = id - self.highest;
            self.bitmap = if shift >= 64 { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.highest = id;
            true
        } else {
            let back = self.highest - id;
            if back >= WINDOW {
                return false; // too old
            }
            let mask = 1u64 << back;
            if self.bitmap & mask != 0 {
                false // already seen
            } else {
                self.bitmap |= mask;
                true
            }
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_accepts_in_order_and_rejects_replays() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0));
        assert!(w.accept(1));
        assert!(w.accept(2));
        assert!(!w.accept(1)); // replay
        assert!(w.accept(100)); // jump forward
        assert!(!w.accept(100)); // replay of the new max
        assert!(w.accept(99)); // within window, not yet seen
        assert!(!w.accept(0)); // far behind the window now -> rejected
    }

    #[test]
    fn window_exact_boundaries() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(100));
        assert!(w.accept(37)); // back == 63: oldest acceptable
        assert!(!w.accept(36)); // back == 64: first rejected
        assert!(w.accept(164)); // shift == 64: window fully clears, new highest marked
        assert!(!w.accept(100)); // back == 64 from the new highest -> rejected
        assert!(w.accept(163)); // back == 1: not yet seen -> accepted
    }
}
