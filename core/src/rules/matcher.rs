//! Compact, coverage-preserving rule matcher (M2).
//!
//! Given several [`RuleSet`]s — each tagged with the [`Action`] its matches should produce — this
//! builds ONE compact structure that maps a flow's destination (domain and/or IP) to an `Action`.
//! The router (M3) supplies rule-sets in descending precedence: `ad_block`(Reject) →
//! `route.rules` → `smart_routing`(Direct); [`Matcher::lookup`] returns the `Action` of the
//! highest-precedence rule that matches, or `None` (caller falls back to `route.final` = Proxy).
//!
//! The point of M2 is the mobile footprint: rather than keep every list as a linear scan, domains
//! collapse into one shared reversed-label suffix trie and IPs into one CIDR trie, with redundant
//! entries dropped WITHOUT changing any lookup result (proven by the property test below).
//!
//! Precedence is carried as a `rank` (the entry's index in the descending-precedence `build`
//! input — 0 is highest). Every terminal stores the *minimum* rank that reaches it; a lookup that
//! hits several terminals returns the action of the smallest rank. Storing the min-rank at build
//! time is what lets a single trie/CIDR walk reflect the full ordering.

use super::srs::{IpCidr, RuleSet};
use super::Action;
use std::collections::HashMap;
use std::net::IpAddr;

/// A precedence rank: the entry's index in the descending-precedence `build` input (0 = highest).
/// A smaller rank wins. Kept as `u16` — mobile rule-sets number in the low tens, never near 65 535.
type Rank = u16;

/// Maps a flow's destination to an [`Action`], compacted to a small footprint without losing
/// coverage. Built once from tagged rule-sets via [`Matcher::build`]; queried per flow via
/// [`Matcher::lookup`].
pub struct Matcher {
    /// The `Action` for each rank, indexed by rank. `actions[rank]` is the action of the entry at
    /// that precedence position.
    actions: Vec<Action>,
    /// Reversed-label suffix trie shared across every entry's `domain` + `domain_suffix` matchers.
    domains: DomainTrie,
    /// Substring keywords, deduped, each carrying the min rank that contributes it. Small by design
    /// (the config's keyword lists are tiny), so a linear scan is fine.
    keywords: Vec<(String, Rank)>,
    /// Longest-prefix IP structure over both families, built from every entry's `ip_cidr`.
    cidrs: CidrTrie,
}

impl Matcher {
    /// Build from rule-sets in DESCENDING precedence order (highest-precedence first). The router
    /// (M3) supplies them `ad_block`(Reject) → `route.rules` → `smart_routing`(Direct); [`lookup`]
    /// returns the `Action` of the highest-precedence rule that matches.
    ///
    /// [`lookup`]: Matcher::lookup
    pub fn build(entries: Vec<(Action, RuleSet)>) -> Matcher {
        let mut actions = Vec::with_capacity(entries.len());
        let mut domains = DomainTrie::default();
        let mut cidrs = CidrTrie::default();
        // Keyword -> min rank, deduped across every list.
        let mut keyword_ranks: HashMap<String, Rank> = HashMap::new();

        for (rank, (action, rs)) in entries.into_iter().enumerate() {
            // Rank saturates rather than wraps if a caller ever exceeds u16 — such an entry then
            // shares the lowest precedence instead of aliasing a high-precedence rank.
            let rank = Rank::try_from(rank).unwrap_or(Rank::MAX);
            actions.push(action);

            for d in rs.domain {
                domains.insert(&normalize(&d), Terminal::Exact, rank);
            }
            for s in rs.domain_suffix {
                domains.insert(&normalize(&s), Terminal::Suffix, rank);
            }
            for k in rs.domain_keyword {
                let k = normalize(&k);
                keyword_ranks
                    .entry(k)
                    .and_modify(|r| *r = (*r).min(rank))
                    .or_insert(rank);
            }
            for c in rs.ip_cidr {
                cidrs.insert(&c, rank);
            }
        }

        // Coverage-preserving compaction: within the same Action, an exact or narrower-suffix
        // terminal is redundant if a broader suffix of the SAME Action already covers it at an
        // equal-or-higher precedence. Dropping it cannot change any lookup. See the trie method.
        domains.compact(&actions);
        cidrs.compact(&actions);

        let mut keywords: Vec<(String, Rank)> = keyword_ranks.into_iter().collect();
        // Deterministic order (rank, then key) so lookups and size reports are reproducible.
        keywords.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));

        Matcher {
            actions,
            domains,
            keywords,
            cidrs,
        }
    }

    /// The [`Action`] for a flow, or `None` if nothing matches (the caller falls back to
    /// `route.final` = Proxy). `domain` is the destination hostname when known (via fake-IP DNS);
    /// `ip` is always available. When both a domain rule and an IP rule match, the higher-precedence
    /// (smaller-rank) one wins.
    pub fn lookup(&self, domain: Option<&str>, ip: IpAddr) -> Option<Action> {
        let mut best: Option<Rank> = None;

        if let Some(d) = domain {
            let d = normalize(d);
            if let Some(r) = self.domains.lookup(&d) {
                best = Some(min_opt(best, r));
            }
            for (kw, r) in &self.keywords {
                // Once a keyword can't beat the current best rank, and the list is rank-sorted, the
                // rest can't either — but the list is tiny, so we just scan and take the min.
                if d.contains(kw.as_str()) {
                    best = Some(min_opt(best, *r));
                }
            }
        }

        if let Some(r) = self.cidrs.lookup(ip) {
            best = Some(min_opt(best, r));
        }

        best.map(|r| self.actions[r as usize])
    }

    /// Total distinct terminals + CIDR entries + keywords retained after compaction. Used by the
    /// compaction-ratio test; not part of the routing path.
    #[cfg(test)]
    fn compacted_len(&self) -> usize {
        self.domains.terminal_count() + self.cidrs.entry_count() + self.keywords.len()
    }
}

/// Lowercase and strip a single trailing `.` (the DNS root dot). Domain matching is
/// case-insensitive, so both build and lookup route every name through here.
fn normalize(domain: &str) -> String {
    let trimmed = domain.strip_suffix('.').unwrap_or(domain);
    trimmed.to_ascii_lowercase()
}

/// `min` of an optional rank and a new rank (smaller rank = higher precedence).
fn min_opt(cur: Option<Rank>, new: Rank) -> Rank {
    match cur {
        Some(c) => c.min(new),
        None => new,
    }
}

// -------------------------------------------------------------------------------------------------
// Domain suffix trie (reversed labels).
// -------------------------------------------------------------------------------------------------

/// Which flavour of terminal a domain rule contributes to a trie node.
#[derive(Clone, Copy)]
enum Terminal {
    /// Exact-match: matches only the identical domain.
    Exact,
    /// Suffix-match: matches the domain itself AND any left-extension at a label boundary.
    Suffix,
}

/// A node in the reversed-label trie. Keys are whole labels (`com`, `discord`, …), so a suffix at a
/// node covers exactly its label-boundary sub-domains — never a partial-label collision like
/// `notdiscord.com` for suffix `discord.com`.
#[derive(Default)]
struct TrieNode {
    /// Child label -> node index in [`DomainTrie::nodes`].
    children: HashMap<String, usize>,
    /// Min rank of a `domain_suffix` rule terminating here (matches this domain + any extension).
    suffix_rank: Option<Rank>,
    /// Min rank of an exact `domain` rule terminating here (matches this domain only).
    exact_rank: Option<Rank>,
}

/// A reversed-label suffix trie shared across all suffix + exact domain entries. Labels are split on
/// `.` and inserted root-last (`app.discord.com` → `com` → `discord` → `app`), so a suffix rule at
/// the `com/discord` node matches `discord.com` and `app.discord.com` but not `notdiscord.com`.
#[derive(Default)]
struct DomainTrie {
    /// Arena of nodes; index 0 is the root. An arena (vs `Box`-linked nodes) keeps the borrow
    /// checker happy during the mutable insert walk and packs the nodes contiguously.
    nodes: Vec<TrieNode>,
}

impl DomainTrie {
    /// Split a domain into labels in reversed (root-first) order. An empty domain yields no labels.
    fn labels(domain: &str) -> impl Iterator<Item = &str> {
        domain.split('.').rev().filter(|l| !l.is_empty())
    }

    /// Insert one domain terminal (exact or suffix) at the given rank, keeping the min rank if the
    /// same terminal is inserted again from another list.
    fn insert(&mut self, domain: &str, kind: Terminal, rank: Rank) {
        if self.nodes.is_empty() {
            self.nodes.push(TrieNode::default());
        }
        let mut cur = 0usize;
        for label in Self::labels(domain) {
            cur = match self.nodes[cur].children.get(label) {
                Some(&next) => next,
                None => {
                    let next = self.nodes.len();
                    self.nodes.push(TrieNode::default());
                    self.nodes[cur].children.insert(label.to_owned(), next);
                    next
                }
            };
        }
        let slot = match kind {
            Terminal::Exact => &mut self.nodes[cur].exact_rank,
            Terminal::Suffix => &mut self.nodes[cur].suffix_rank,
        };
        *slot = Some(match *slot {
            Some(existing) => existing.min(rank),
            None => rank,
        });
    }

    /// The min rank matching `domain`, or `None`. Walks root-first labels: any suffix terminal on
    /// the path covers the domain (a suffix at an ancestor matches every extension); the exact
    /// terminal at the full path matches only the identical domain.
    fn lookup(&self, domain: &str) -> Option<Rank> {
        if self.nodes.is_empty() {
            return None;
        }
        let mut best: Option<Rank> = None;
        let mut cur = 0usize;
        // A suffix at the root would match everything; we never insert one (an empty suffix isn't a
        // valid rule), so the root's suffix_rank stays None and the walk starts clean.
        let mut labels = Self::labels(domain).peekable();
        while let Some(label) = labels.next() {
            let next = match self.nodes[cur].children.get(label) {
                Some(&n) => n,
                None => return best, // no deeper node → only ancestor suffixes (already folded in)
            };
            cur = next;
            if let Some(r) = self.nodes[cur].suffix_rank {
                best = Some(min_opt(best, r));
            }
            // The exact terminal only counts when this node is the END of the domain's labels.
            if labels.peek().is_none() {
                if let Some(r) = self.nodes[cur].exact_rank {
                    best = Some(min_opt(best, r));
                }
            }
        }
        best
    }

    /// Coverage-preserving compaction. For each node, if an ANCESTOR carries a suffix terminal whose
    /// [`Action`] equals this node's terminal's action at an equal-or-higher precedence (rank ≤),
    /// this node's terminal is redundant — the ancestor suffix already yields the same action for
    /// this domain and every extension of it — so drop it. This is the "collapse redundant children
    /// under a covering suffix" step. Terminals of a DIFFERENT action are never dropped (different
    /// outcome). A domain covered by suffixes of two actions keeps only the higher-precedence one.
    fn compact(&mut self, actions: &[Action]) {
        if self.nodes.is_empty() {
            return;
        }
        // DFS from the root carrying, per Action, the best (min) suffix rank seen on the path so far
        // (ancestors only — a node's own suffix cannot cover its own exact terminal's *narrower*
        // meaning, but it CAN make a same-node exact of equal/lower precedence redundant, handled
        // explicitly below).
        struct Frame {
            node: usize,
            // Best suffix rank per action seen strictly above this node.
            covering: [Option<Rank>; 3],
        }
        let mut stack = vec![Frame {
            node: 0,
            covering: [None; 3],
        }];
        while let Some(Frame { node, covering }) = stack.pop() {
            // A suffix at THIS node covering the same action at equal/higher precedence makes this
            // node's exact terminal redundant (suffix matches the domain itself too).
            if let Some(exact_rank) = self.nodes[node].exact_rank {
                let act = action_index(actions[exact_rank as usize]);
                let covered_by_ancestor = is_covered(covering[act], exact_rank);
                let covered_by_self = match self.nodes[node].suffix_rank {
                    Some(sr) if action_index(actions[sr as usize]) == act => sr <= exact_rank,
                    _ => false,
                };
                if covered_by_ancestor || covered_by_self {
                    self.nodes[node].exact_rank = None;
                }
            }
            // A suffix at THIS node is redundant if an ancestor suffix of the same action already
            // covers it at equal/higher precedence.
            if let Some(suffix_rank) = self.nodes[node].suffix_rank {
                let act = action_index(actions[suffix_rank as usize]);
                if is_covered(covering[act], suffix_rank) {
                    self.nodes[node].suffix_rank = None;
                }
            }

            // Extend the covering map with this node's (possibly just-dropped, but then it was
            // redundant anyway) surviving suffix for descendants.
            let mut child_cover = covering;
            if let Some(sr) = self.nodes[node].suffix_rank {
                let act = action_index(actions[sr as usize]);
                child_cover[act] = Some(match child_cover[act] {
                    Some(c) => c.min(sr),
                    None => sr,
                });
            }
            for &child in self.nodes[node].children.values() {
                stack.push(Frame {
                    node: child,
                    covering: child_cover,
                });
            }
        }
    }

    /// Count of surviving terminals (exact + suffix) after compaction — the compacted domain size.
    #[cfg(test)]
    fn terminal_count(&self) -> usize {
        self.nodes
            .iter()
            .map(|n| n.suffix_rank.is_some() as usize + n.exact_rank.is_some() as usize)
            .sum()
    }
}

/// A covering suffix of rank `cover` makes a terminal of rank `victim` redundant iff it exists and
/// is equal-or-higher precedence (`cover <= victim`). Same-action is the caller's precondition.
fn is_covered(cover: Option<Rank>, victim: Rank) -> bool {
    matches!(cover, Some(c) if c <= victim)
}

/// Map an [`Action`] to a small dense index for the per-action covering arrays.
fn action_index(a: Action) -> usize {
    match a {
        Action::Proxy => 0,
        Action::Direct => 1,
        Action::Reject => 2,
    }
}

// -------------------------------------------------------------------------------------------------
// CIDR trie (longest-prefix match over both families).
// -------------------------------------------------------------------------------------------------

/// A bit-trie over IP prefixes (v4 and v6 kept in separate roots). Each edge is one address bit
/// (MSB first); a prefix terminates at depth = its prefix length, carrying the min rank. Lookup
/// walks the address bits and takes the min rank across EVERY containing prefix on the path — which
/// is the precedence semantics (highest-precedence containing rule wins), NOT longest-prefix. This
/// deliberately matches the naive scan: it returns the first entry (by precedence) whose any CIDR
/// contains the address, regardless of that CIDR's width.
#[derive(Default)]
struct CidrTrie {
    v4: BitTrie,
    v6: BitTrie,
}

impl CidrTrie {
    fn insert(&mut self, cidr: &IpCidr, rank: Rank) {
        match cidr.addr {
            IpAddr::V4(a) => {
                let bits = u32::from(a) as u128;
                // Left-align the v4 bits into the top 32 of the u128 so a shared walk works.
                self.v4.insert(bits << 96, cidr.prefix, 32, rank);
            }
            IpAddr::V6(a) => {
                self.v6.insert(u128::from(a), cidr.prefix, 128, rank);
            }
        }
    }

    fn lookup(&self, ip: IpAddr) -> Option<Rank> {
        match ip {
            IpAddr::V4(a) => self.v4.lookup((u32::from(a) as u128) << 96, 32),
            IpAddr::V6(a) => self.v6.lookup(u128::from(a), 128),
        }
    }

    /// Coverage-preserving compaction: a prefix contained in a broader prefix of the SAME action at
    /// equal-or-higher precedence is redundant (the broader one yields the same action for every
    /// address it covers, including this narrower block), so drop it.
    fn compact(&mut self, actions: &[Action]) {
        self.v4.compact(actions);
        self.v6.compact(actions);
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.v4.terminal_count() + self.v6.terminal_count()
    }
}

/// One binary trie (per family). Node 0 is the root (the /0 prefix). `bit[0]` is the child for a 0
/// bit, `bit[1]` for a 1 bit. `rank` is set at the node whose depth equals a stored prefix length.
#[derive(Default)]
struct BitTrie {
    nodes: Vec<BitNode>,
}

#[derive(Default)]
struct BitNode {
    /// Children for a 0-bit and a 1-bit respectively; `usize::MAX` = absent.
    child: [usize; 2],
    /// Min rank of a prefix terminating exactly at this node's depth, if any.
    rank: Option<Rank>,
}

const NO_CHILD: usize = usize::MAX;

impl BitTrie {
    fn ensure_root(&mut self) {
        if self.nodes.is_empty() {
            self.nodes.push(BitNode {
                child: [NO_CHILD, NO_CHILD],
                rank: None,
            });
        }
    }

    /// Insert a left-aligned `addr` (MSB first) with `prefix` significant bits (`prefix <=
    /// max_bits`), keeping the min rank on collision.
    fn insert(&mut self, addr: u128, prefix: u8, max_bits: u8, rank: Rank) {
        self.ensure_root();
        let depth = prefix.min(max_bits);
        let mut cur = 0usize;
        for i in 0..depth {
            let bit = ((addr >> (127 - i)) & 1) as usize;
            cur = match self.nodes[cur].child[bit] {
                NO_CHILD => {
                    let next = self.nodes.len();
                    self.nodes.push(BitNode {
                        child: [NO_CHILD, NO_CHILD],
                        rank: None,
                    });
                    self.nodes[cur].child[bit] = next;
                    next
                }
                next => next,
            };
        }
        self.nodes[cur].rank = Some(match self.nodes[cur].rank {
            Some(existing) => existing.min(rank),
            None => rank,
        });
    }

    /// Precedence match: walk `addr`'s bits and take the min rank across every containing prefix on
    /// the path (each ancestor prefix contains `addr`). The smallest rank = highest precedence,
    /// which is what the naive precedence scan returns — a broader higher-precedence CIDR beats a
    /// narrower lower-precedence one, so this is min-rank, not longest-prefix.
    fn lookup(&self, addr: u128, max_bits: u8) -> Option<Rank> {
        if self.nodes.is_empty() {
            return None;
        }
        let mut best: Option<Rank> = None;
        let mut cur = 0usize;
        if let Some(r) = self.nodes[cur].rank {
            best = Some(r); // a /0 prefix matches everything
        }
        for i in 0..max_bits {
            let bit = ((addr >> (127 - i)) & 1) as usize;
            cur = match self.nodes[cur].child[bit] {
                NO_CHILD => break,
                next => next,
            };
            if let Some(r) = self.nodes[cur].rank {
                best = Some(min_opt(best, r));
            }
        }
        best
    }

    /// Drop any terminal an ancestor terminal of the SAME action covers at equal-or-higher
    /// precedence (rank ≤). An ancestor in a bit-trie is a strictly-broader containing prefix, so
    /// this is exactly "narrower prefix contained in a broader same-action prefix is redundant".
    fn compact(&mut self, actions: &[Action]) {
        if self.nodes.is_empty() {
            return;
        }
        struct Frame {
            node: usize,
            covering: [Option<Rank>; 3],
        }
        let mut stack = vec![Frame {
            node: 0,
            covering: [None; 3],
        }];
        while let Some(Frame { node, covering }) = stack.pop() {
            if let Some(rank) = self.nodes[node].rank {
                let act = action_index(actions[rank as usize]);
                if is_covered(covering[act], rank) {
                    self.nodes[node].rank = None;
                }
            }
            let mut child_cover = covering;
            if let Some(r) = self.nodes[node].rank {
                let act = action_index(actions[r as usize]);
                child_cover[act] = Some(match child_cover[act] {
                    Some(c) => c.min(r),
                    None => r,
                });
            }
            for &child in &self.nodes[node].child {
                if child != NO_CHILD {
                    stack.push(Frame {
                        node: child,
                        covering: child_cover,
                    });
                }
            }
        }
    }

    #[cfg(test)]
    fn terminal_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.rank.is_some()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::srs::{self, IpCidr};

    /// `cargo test` runs with `core/` as the working directory, so real fixtures resolve here.
    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("tests/fixtures/srs/{name}.srs"))
            .unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
    }

    fn rs_suffix(suffixes: &[&str]) -> RuleSet {
        RuleSet {
            domain_suffix: suffixes.iter().map(|s| s.to_string()).collect(),
            ..RuleSet::default()
        }
    }

    fn cidr(s: &str) -> IpCidr {
        let (addr, pfx) = s.split_once('/').expect("cidr has a /");
        IpCidr {
            addr: addr.parse().expect("addr"),
            prefix: pfx.parse().expect("prefix"),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    // --- 1. Unit semantics -----------------------------------------------------------------------

    #[test]
    fn suffix_matches_domain_and_subdomains_at_label_boundary() {
        let m = Matcher::build(vec![(Action::Direct, rs_suffix(&["discord.com"]))]);
        // The suffix matches the domain itself and any left-extension at a label boundary.
        assert_eq!(
            m.lookup(Some("discord.com"), ip("1.1.1.1")),
            Some(Action::Direct)
        );
        assert_eq!(
            m.lookup(Some("app.discord.com"), ip("1.1.1.1")),
            Some(Action::Direct)
        );
        // ...but NOT a partial-label collision, and NOT a different TLD.
        assert_eq!(m.lookup(Some("notdiscord.com"), ip("1.1.1.1")), None);
        assert_eq!(m.lookup(Some("discord.company"), ip("1.1.1.1")), None);
    }

    #[test]
    fn exact_matches_only_identical_domain() {
        let m = Matcher::build(vec![(
            Action::Reject,
            RuleSet {
                domain: vec!["ads.example.com".into()],
                ..RuleSet::default()
            },
        )]);
        assert_eq!(
            m.lookup(Some("ads.example.com"), ip("1.1.1.1")),
            Some(Action::Reject)
        );
        // Exact does not cover sub-domains or parents.
        assert_eq!(m.lookup(Some("x.ads.example.com"), ip("1.1.1.1")), None);
        assert_eq!(m.lookup(Some("example.com"), ip("1.1.1.1")), None);
    }

    #[test]
    fn keyword_matches_substring() {
        let m = Matcher::build(vec![(
            Action::Reject,
            RuleSet {
                domain_keyword: vec!["doubleclick".into()],
                ..RuleSet::default()
            },
        )]);
        assert_eq!(
            m.lookup(Some("stats.doubleclick.net"), ip("1.1.1.1")),
            Some(Action::Reject)
        );
        assert_eq!(m.lookup(Some("example.com"), ip("1.1.1.1")), None);
    }

    #[test]
    fn cidr_longest_prefix_and_both_families() {
        let m = Matcher::build(vec![(
            Action::Reject,
            RuleSet {
                ip_cidr: vec![cidr("10.0.0.0/8"), cidr("2001:db8::/32")],
                ..RuleSet::default()
            },
        )]);
        assert_eq!(m.lookup(None, ip("10.1.2.3")), Some(Action::Reject));
        assert_eq!(m.lookup(None, ip("11.0.0.1")), None);
        assert_eq!(m.lookup(None, ip("2001:db8::dead")), Some(Action::Reject));
        assert_eq!(m.lookup(None, ip("2001:dead::1")), None);
    }

    #[test]
    fn precedence_higher_entry_wins() {
        // Reject listed FIRST (highest precedence); the same domain is also in a Direct list.
        let m = Matcher::build(vec![
            (Action::Reject, rs_suffix(&["shared.example"])),
            (Action::Direct, rs_suffix(&["shared.example"])),
        ]);
        assert_eq!(
            m.lookup(Some("shared.example"), ip("1.1.1.1")),
            Some(Action::Reject)
        );
        assert_eq!(
            m.lookup(Some("a.shared.example"), ip("1.1.1.1")),
            Some(Action::Reject)
        );

        // Reversed precedence: Direct first now wins for the same domain.
        let m2 = Matcher::build(vec![
            (Action::Direct, rs_suffix(&["shared.example"])),
            (Action::Reject, rs_suffix(&["shared.example"])),
        ]);
        assert_eq!(
            m2.lookup(Some("shared.example"), ip("1.1.1.1")),
            Some(Action::Direct)
        );
    }

    #[test]
    fn case_insensitive_and_trailing_dot() {
        let m = Matcher::build(vec![(Action::Direct, rs_suffix(&["Discord.COM"]))]);
        assert_eq!(
            m.lookup(Some("APP.Discord.Com."), ip("1.1.1.1")),
            Some(Action::Direct)
        );
    }

    #[test]
    fn domain_and_ip_both_match_precedence_wins() {
        // Domain says Direct (rank 1), IP says Reject (rank 0). Reject is higher precedence.
        let m = Matcher::build(vec![
            (
                Action::Reject,
                RuleSet {
                    ip_cidr: vec![cidr("203.0.113.0/24")],
                    ..RuleSet::default()
                },
            ),
            (Action::Direct, rs_suffix(&["example.org"])),
        ]);
        assert_eq!(
            m.lookup(Some("example.org"), ip("203.0.113.7")),
            Some(Action::Reject)
        );
        // Same domain, an IP outside the CIDR → only the domain rule fires.
        assert_eq!(
            m.lookup(Some("example.org"), ip("8.8.8.8")),
            Some(Action::Direct)
        );
    }

    // --- 2. Real fixtures, end-to-end ------------------------------------------------------------

    fn build_from_fixtures() -> Matcher {
        // Reject-first for precedence: ad/malware lists, then the common-direct list.
        let banad = srs::parse(&fixture("banad_v1")).expect("parse banad_v1");
        let cat_ads = srs::parse(&fixture("category-ads_v2")).expect("parse category-ads_v2");
        let malware = srs::parse(&fixture("geoip-malware")).expect("parse geoip-malware");
        let common = srs::parse(&fixture("common_v3")).expect("parse common_v3");
        Matcher::build(vec![
            (Action::Reject, banad),
            (Action::Reject, cat_ads),
            (Action::Reject, malware),
            (Action::Direct, common),
        ])
    }

    #[test]
    fn fixtures_end_to_end() {
        let m = build_from_fixtures();

        // A known ad domain is rejected.
        assert_eq!(
            m.lookup(Some("doubleclick.net"), ip("8.8.8.8")),
            Some(Action::Reject)
        );
        assert_eq!(
            m.lookup(Some("ad.doubleclick.net"), ip("8.8.8.8")),
            Some(Action::Reject)
        );

        // A common_v3 suffix routes Direct (discord.com is present in that fixture's suffix set).
        let common = srs::parse(&fixture("common_v3")).expect("parse common_v3");
        assert!(
            common.domain_suffix.iter().any(|s| s == "discord.com"),
            "fixture precondition: common_v3 carries the discord.com suffix"
        );
        assert_eq!(
            m.lookup(Some("discord.com"), ip("8.8.8.8")),
            Some(Action::Direct)
        );
        assert_eq!(
            m.lookup(Some("app.discord.com"), ip("8.8.8.8")),
            Some(Action::Direct)
        );

        // An unlisted domain matches nothing.
        assert_eq!(
            m.lookup(Some("example-unlisted-xyz.test"), ip("8.8.8.8")),
            None
        );
    }

    // --- 3. Property test: compaction preserves results ------------------------------------------

    /// Naive reference matcher: a linear scan over the RAW (uncompacted) entries in precedence
    /// order, applying the exact same semantics as [`Matcher`]. The first (highest-precedence)
    /// entry that matches wins.
    fn naive_lookup(
        entries: &[(Action, RuleSet)],
        domain: Option<&str>,
        ip: IpAddr,
    ) -> Option<Action> {
        for (action, rs) in entries {
            if let Some(d) = domain {
                let d = normalize(d);
                if rs.domain.iter().any(|e| normalize(e) == d) {
                    return Some(*action);
                }
                if rs
                    .domain_suffix
                    .iter()
                    .any(|s| suffix_matches(&normalize(s), &d))
                {
                    return Some(*action);
                }
                if rs.domain_keyword.iter().any(|k| d.contains(&normalize(k))) {
                    return Some(*action);
                }
            }
            if rs.ip_cidr.iter().any(|c| cidr_contains(c, ip)) {
                return Some(*action);
            }
        }
        None
    }

    /// Reference suffix semantics: `suffix` matches `domain` itself and any left-extension at a
    /// label boundary.
    fn suffix_matches(suffix: &str, domain: &str) -> bool {
        if domain == suffix {
            return true;
        }
        match domain.strip_suffix(suffix) {
            Some(prefix) => prefix.ends_with('.'),
            None => false,
        }
    }

    /// Reference CIDR containment for one address.
    fn cidr_contains(c: &IpCidr, ip: IpAddr) -> bool {
        match (c.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(a)) => {
                let shift = 32u32.saturating_sub(c.prefix as u32);
                let mask = if shift >= 32 { 0 } else { u32::MAX << shift };
                (u32::from(net) & mask) == (u32::from(a) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(a)) => {
                let shift = 128u32.saturating_sub(c.prefix as u32);
                let mask = if shift >= 128 { 0 } else { u128::MAX << shift };
                (u128::from(net) & mask) == (u128::from(a) & mask)
            }
            _ => false,
        }
    }

    /// A tiny deterministic PRNG (xorshift64*) so the property test needs no `rand` crate.
    struct Rng(u64);
    impl Rng {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
    }

    #[test]
    fn compaction_preserves_lookup_over_large_sample() {
        let entries = vec![
            (
                Action::Reject,
                srs::parse(&fixture("banad_v1")).expect("parse banad_v1"),
            ),
            (
                Action::Reject,
                srs::parse(&fixture("category-ads_v2")).expect("parse category-ads_v2"),
            ),
            (
                Action::Reject,
                srs::parse(&fixture("geoip-malware")).expect("parse geoip-malware"),
            ),
            (
                Action::Direct,
                srs::parse(&fixture("common_v3")).expect("parse common_v3"),
            ),
        ];
        let m = Matcher::build(entries.clone());

        // Build the domain sample: every fixture entry + a `x.<entry>` left-extension + a batch of
        // random unlisted names. A fixed IP (unmatched by any CIDR here) isolates the domain path.
        let probe_ip = ip("192.0.2.123"); // TEST-NET-1; not in any fixture CIDR
        let mut domains: Vec<String> = Vec::new();
        for (_, rs) in &entries {
            for d in rs.domain.iter().chain(rs.domain_suffix.iter()) {
                domains.push(d.clone());
                domains.push(format!("x.{d}"));
            }
            for k in &rs.domain_keyword {
                domains.push(format!("pre{k}post.example"));
            }
        }
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..2000 {
            let n = (rng.next_u64() % 4) + 1;
            let mut parts = Vec::new();
            for _ in 0..n {
                let len = (rng.next_u64() % 6) + 2;
                let label: String = (0..len)
                    .map(|_| (b'a' + (rng.next_u64() % 26) as u8) as char)
                    .collect();
                parts.push(label);
            }
            domains.push(parts.join("."));
        }

        for d in &domains {
            let want = naive_lookup(&entries, Some(d), probe_ip);
            let got = m.lookup(Some(d), probe_ip);
            assert_eq!(
                got, want,
                "domain lookup mismatch for {d:?}: got {got:?}, want {want:?}"
            );
        }

        // IP sample: addresses inside and outside the geoip CIDRs, plus randoms.
        let malware = srs::parse(&fixture("geoip-malware")).expect("parse geoip-malware");
        let mut ips: Vec<IpAddr> = Vec::new();
        for c in malware.ip_cidr.iter().take(200) {
            // The network address itself is inside the block.
            ips.push(c.addr);
            // A nearby address; may be inside or outside depending on prefix width.
            match c.addr {
                IpAddr::V4(a) => {
                    ips.push(IpAddr::V4((u32::from(a).wrapping_add(1)).into()));
                    ips.push(IpAddr::V4((u32::from(a) ^ 0x0000_00ff).into()));
                }
                IpAddr::V6(a) => {
                    ips.push(IpAddr::V6((u128::from(a).wrapping_add(1)).into()));
                }
            }
        }
        for _ in 0..2000 {
            ips.push(IpAddr::V4((rng.next_u64() as u32).into()));
        }
        for _ in 0..500 {
            let hi = rng.next_u64() as u128;
            let lo = rng.next_u64() as u128;
            ips.push(IpAddr::V6(((hi << 64) | lo).into()));
        }
        // Cross the domain and IP paths too: a listed ad domain against random IPs.
        for &probe in &ips {
            let want = naive_lookup(&entries, None, probe);
            let got = m.lookup(None, probe);
            assert_eq!(
                got, want,
                "ip lookup mismatch for {probe}: got {got:?}, want {want:?}"
            );
            // Domain + IP combined must also agree with the naive scan.
            let want2 = naive_lookup(&entries, Some("doubleclick.net"), probe);
            let got2 = m.lookup(Some("doubleclick.net"), probe);
            assert_eq!(got2, want2, "combined lookup mismatch at {probe}");
        }
    }

    // --- 4. Compaction win report ----------------------------------------------------------------

    #[test]
    fn reports_compaction_win() {
        let entries = vec![
            (
                Action::Reject,
                srs::parse(&fixture("banad_v1")).expect("parse banad_v1"),
            ),
            (
                Action::Reject,
                srs::parse(&fixture("category-ads_v2")).expect("parse category-ads_v2"),
            ),
            (
                Action::Reject,
                srs::parse(&fixture("geoip-malware")).expect("parse geoip-malware"),
            ),
            (
                Action::Direct,
                srs::parse(&fixture("common_v3")).expect("parse common_v3"),
            ),
        ];
        let raw: usize = entries
            .iter()
            .map(|(_, rs)| {
                rs.domain.len()
                    + rs.domain_suffix.len()
                    + rs.domain_keyword.len()
                    + rs.ip_cidr.len()
            })
            .sum();
        let m = Matcher::build(entries);
        let compacted = m.compacted_len();
        eprintln!(
            "compaction: raw entries = {raw}, compacted terminals+cidrs+keywords = {compacted} \
             (ratio {:.3})",
            compacted as f64 / raw as f64
        );
        assert!(
            compacted <= raw,
            "compacted ({compacted}) must not exceed raw ({raw})"
        );
    }
}
