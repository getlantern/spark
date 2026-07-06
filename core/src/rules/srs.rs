//! Parser for sing-box compiled rule-sets (`.srs`).
//!
//! Wire format (pinned against the real getlantern/KaringX rule-sets in the config): ASCII `"SRS"`
//! magic (3 bytes) + a 1-byte version + a zlib stream. Versions 1, 2, and 3 are all in active use
//! across the configured rule-sets, so all three are accepted. The decompressed body is a
//! `uvarint` rule count followed by typed rule records; domains are stored in sing-box's succinct
//! domain set. Authoritative encoding: `sagernet/sing-box` `common/srs` + `sagernet/sing`
//! `common/domain`.
//!
//! [`parse`] decodes the envelope, walks the rule records, and merges every rule's matchers into a
//! single [`RuleSet`] (`domain` / `domain_suffix` / `domain_keyword` / `ip_cidr`). Item types the
//! Lantern config never uses (`domain_regex`, ports, process/package names, WiFi, AdGuard, …) are
//! consumed and ignored rather than rejected, so a rule-set carrying them still parses.

use std::fmt;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Errors from parsing a sing-box `.srs` rule-set.
#[derive(Debug, thiserror::Error)]
pub enum SrsError {
    /// The input does not start with the `"SRS"` magic.
    #[error(".srs: bad magic (not \"SRS\")")]
    BadMagic,
    /// The input ended before a required field was fully read.
    #[error(".srs: truncated input")]
    Truncated,
    /// The version byte is outside the supported range (1..=3).
    #[error(".srs: unsupported version {0} (supported: 1..=3)")]
    UnsupportedVersion(u8),
    /// The zlib body failed to inflate.
    #[error(".srs: zlib inflate failed: {0}")]
    Inflate(#[from] std::io::Error),
    /// The decompressed rule body was malformed.
    #[error(".srs: malformed rule body: {0}")]
    Malformed(&'static str),
}

/// The `"SRS"` magic that prefixes every rule-set.
const MAGIC: &[u8; 3] = b"SRS";

/// The `.srs` envelope after magic + version have been stripped and the body inflated.
#[derive(Debug)]
pub(crate) struct Envelope {
    /// The format version byte (1, 2, or 3). Validated by `decode_envelope` and asserted by the
    /// envelope test, but not branched on by the reader: sing-box's `.srs` decode is
    /// version-agnostic (every item body is self-describing; the v1/v2/v3 gates are write-side
    /// only). Retained as decoded envelope metadata a future caller may want to log.
    #[allow(dead_code)]
    pub version: u8,
    /// The zlib-inflated rule body.
    pub body: Vec<u8>,
}

/// Decode the `.srs` envelope: 3-byte `"SRS"` magic, a 1-byte version (1..=3), then a zlib stream.
pub(crate) fn decode_envelope(bytes: &[u8]) -> Result<Envelope, SrsError> {
    if bytes.len() < 4 {
        return Err(SrsError::Truncated);
    }
    if &bytes[..3] != MAGIC {
        return Err(SrsError::BadMagic);
    }
    let version = bytes[3];
    if !(1..=3).contains(&version) {
        return Err(SrsError::UnsupportedVersion(version));
    }
    let mut body = Vec::new();
    flate2::read::ZlibDecoder::new(&bytes[4..]).read_to_end(&mut body)?;
    Ok(Envelope { version, body })
}

/// A forward cursor over the inflated rule body. Every read is bounds-checked and returns
/// [`SrsError::Truncated`] on a short buffer — no panics, no `unwrap`.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Read one byte.
    fn u8(&mut self) -> Result<u8, SrsError> {
        let b = *self.buf.get(self.pos).ok_or(SrsError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    /// Read exactly `n` bytes, borrowing from the underlying buffer.
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], SrsError> {
        let end = self.pos.checked_add(n).ok_or(SrsError::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(SrsError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    /// Read a big-endian `u64` (Go's `binary.Read(_, BigEndian, &v)` for a fixed 8-byte field).
    fn u64_be(&mut self) -> Result<u64, SrsError> {
        let b = self.bytes(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Read a LEB128 unsigned varint (matches Go's `encoding/binary.Uvarint`, ≤10 bytes for a u64).
    fn uvarint(&mut self) -> Result<u64, SrsError> {
        let mut result: u64 = 0;
        for i in 0..10 {
            let b = self.u8()?;
            if i == 9 && b > 1 {
                return Err(SrsError::Malformed("uvarint overflows u64"));
            }
            result |= u64::from(b & 0x7f) << (7 * i);
            if b & 0x80 == 0 {
                return Ok(result);
            }
        }
        Err(SrsError::Malformed("uvarint too long"))
    }

    /// Read a `uvarint`-length-prefixed UTF-8 string.
    fn string(&mut self) -> Result<&'a str, SrsError> {
        let len =
            usize::try_from(self.uvarint()?).map_err(|_| SrsError::Malformed("string len"))?;
        let s = self.bytes(len)?;
        std::str::from_utf8(s).map_err(|_| SrsError::Malformed("non-UTF-8 string"))
    }

    /// Read a `uvarint` as a `usize` (for slice/array lengths), erroring on a >`usize` value.
    fn uvarint_usize(&mut self) -> Result<usize, SrsError> {
        usize::try_from(self.uvarint()?).map_err(|_| SrsError::Malformed("length overflows usize"))
    }
}

// ---------------------------------------------------------------------------------------------
// Rule item + logical-mode tags (sing-box `common/srs/binary.go`, `iota`-numbered; Final = 0xFF).
// ---------------------------------------------------------------------------------------------

const ITEM_QUERY_TYPE: u8 = 0;
const ITEM_NETWORK: u8 = 1;
const ITEM_DOMAIN: u8 = 2;
const ITEM_DOMAIN_KEYWORD: u8 = 3;
const ITEM_DOMAIN_REGEX: u8 = 4;
const ITEM_SOURCE_IP_CIDR: u8 = 5;
const ITEM_IP_CIDR: u8 = 6;
const ITEM_SOURCE_PORT: u8 = 7;
const ITEM_SOURCE_PORT_RANGE: u8 = 8;
const ITEM_PORT: u8 = 9;
const ITEM_PORT_RANGE: u8 = 10;
const ITEM_PROCESS_NAME: u8 = 11;
const ITEM_PROCESS_PATH: u8 = 12;
const ITEM_PACKAGE_NAME: u8 = 13;
const ITEM_WIFI_SSID: u8 = 14;
const ITEM_WIFI_BSSID: u8 = 15;
const ITEM_ADGUARD_DOMAIN: u8 = 16;
const ITEM_PROCESS_PATH_REGEX: u8 = 17;
const ITEM_NETWORK_TYPE: u8 = 18;
const ITEM_NETWORK_IS_EXPENSIVE: u8 = 19;
const ITEM_NETWORK_IS_CONSTRAINED: u8 = 20;
const ITEM_FINAL: u8 = 0xFF;

const RULE_TYPE_DEFAULT: u8 = 0;
const RULE_TYPE_LOGICAL: u8 = 1;

/// The sentinel labels sing prepends to a reversed domain to distinguish a `domain_suffix` from an
/// exact `domain` inside the succinct set (`sing/common/domain/matcher.go`).
const PREFIX_LABEL: u8 = b'\r'; // a leading-`.` suffix (`.example.com`) — matches `foo.example.com`
const ROOT_LABEL: u8 = b'\n'; // a bare suffix (`example.com`) in the v2+ non-legacy encoding

/// An IP/CIDR entry decoded from a `.srs` IPCIDR rule item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpCidr {
    /// The network address (already masked to `prefix` bits by the encoder).
    pub addr: IpAddr,
    /// The prefix length in bits (0..=32 for IPv4, 0..=128 for IPv6).
    pub prefix: u8,
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// The merged matchers of every rule in a `.srs` file.
///
/// A single file's rules are unioned: the config uses one default rule per rule-set, but nested
/// logical rules and multi-rule files both accumulate into the same four vectors.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RuleSet {
    /// Exact-match domains (`example.com` matches only `example.com`).
    pub domain: Vec<String>,
    /// Suffix-match domains (`example.com` matches `example.com` and `*.example.com`).
    pub domain_suffix: Vec<String>,
    /// Substring-match keywords.
    pub domain_keyword: Vec<String>,
    /// IP/CIDR entries.
    pub ip_cidr: Vec<IpCidr>,
}

impl RuleSet {
    /// A rule-set carrying only IP/CIDR entries — used to fold inline `route.rules` (which have no
    /// domain component) into the matcher alongside the parsed `.srs` rule-sets.
    pub fn ip_only(ip_cidr: Vec<IpCidr>) -> Self {
        Self {
            domain: Vec::new(),
            domain_suffix: Vec::new(),
            domain_keyword: Vec::new(),
            ip_cidr,
        }
    }

    /// A rule-set from the user's split-tunnel bypass list: domains become suffix matches (host +
    /// subdomains), IPs/CIDRs become `ip_cidr`. Unparseable IP entries are dropped (the UI validates
    /// on add, so this is belt-and-suspenders).
    pub fn from_domains_and_ips(domains: &[String], ips: &[String]) -> Self {
        Self {
            domain: Vec::new(),
            domain_suffix: domains.to_vec(),
            domain_keyword: Vec::new(),
            ip_cidr: ips.iter().filter_map(|s| parse_ip_or_cidr(s)).collect(),
        }
    }
}

/// Parse a bare IP (`1.2.3.4`, `::1`) or a CIDR (`10.0.0.0/8`) into an [`IpCidr`]. A bare IP gets a
/// host prefix (/32 or /128). `None` on malformed input or an out-of-range prefix.
pub(crate) fn parse_ip_or_cidr(s: &str) -> Option<IpCidr> {
    let s = s.trim();
    match s.split_once('/') {
        Some((addr_s, prefix_s)) => {
            let addr: IpAddr = addr_s.trim().parse().ok()?;
            let prefix: u8 = prefix_s.trim().parse().ok()?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            (prefix <= max).then_some(IpCidr { addr, prefix })
        }
        None => {
            let addr: IpAddr = s.parse().ok()?;
            let prefix = if addr.is_ipv4() { 32 } else { 128 };
            Some(IpCidr { addr, prefix })
        }
    }
}

/// Parse a compiled sing-box `.srs` rule-set into its merged [`RuleSet`].
///
/// Decodes the envelope (magic + version + zlib), reads the `uvarint` rule count, then walks each
/// rule — default rules directly, logical rules recursively — merging every domain / IP matcher.
/// Item types the config never uses are consumed and skipped. Malformed input yields an
/// [`SrsError`]; this function never panics.
pub fn parse(bytes: &[u8]) -> Result<RuleSet, SrsError> {
    let env = decode_envelope(bytes)?;
    let mut r = Reader::new(&env.body);
    let mut out = RuleSet::default();
    let rule_count = r.uvarint_usize()?;
    for _ in 0..rule_count {
        read_rule(&mut r, &mut out)?;
    }
    Ok(out)
}

/// Read one rule (default or logical) and merge its matchers into `out`.
///
/// The record layout is version-independent on the read path: sing-box's `Read`/`readDefaultRule`
/// dispatch every item type uniformly (the v1/v2/v3 gates live only on the *write* side), and each
/// item's body is self-describing — the succinct set carries its own arrays, the IP set its own
/// version byte. The one place the version shows through, the legacy v1 double-encoding of suffixes,
/// is absorbed by [`dump_domains`] exactly as sing's `Matcher.Dump` does, so no version is threaded.
fn read_rule(r: &mut Reader, out: &mut RuleSet) -> Result<(), SrsError> {
    match r.u8()? {
        RULE_TYPE_DEFAULT => read_default_rule(r, out),
        RULE_TYPE_LOGICAL => read_logical_rule(r, out),
        _ => Err(SrsError::Malformed("unknown rule type")),
    }
}

/// Read a logical rule: a mode byte, a `uvarint` sub-rule count, the sub-rules, then the invert byte.
/// The AND/OR mode is irrelevant to us — we union every leaf matcher regardless.
fn read_logical_rule(r: &mut Reader, out: &mut RuleSet) -> Result<(), SrsError> {
    let mode = r.u8()?;
    if mode > 1 {
        return Err(SrsError::Malformed("unknown logical mode"));
    }
    let sub_count = r.uvarint_usize()?;
    for _ in 0..sub_count {
        read_rule(r, out)?;
    }
    let _invert = r.u8()?; // bool
    Ok(())
}

/// Read a default rule: a sequence of items, each tagged by a leading `u8`, ending at
/// [`ITEM_FINAL`] (which is followed by the invert bool). Mirrors sing-box `readDefaultRule`.
fn read_default_rule(r: &mut Reader, out: &mut RuleSet) -> Result<(), SrsError> {
    loop {
        let item_type = r.u8()?;
        match item_type {
            ITEM_DOMAIN => read_domain_item(r, out)?,
            ITEM_DOMAIN_KEYWORD => {
                out.domain_keyword
                    .extend(read_string_list(r)?.into_iter().map(str::to_owned));
            }
            ITEM_IP_CIDR | ITEM_SOURCE_IP_CIDR => {
                let cidrs = read_ip_set(r)?;
                // Only the destination IPCIDR feeds routing; source CIDRs are consumed but dropped.
                if item_type == ITEM_IP_CIDR {
                    out.ip_cidr.extend(cidrs);
                }
            }
            // Consume-and-ignore: item types the config doesn't use. Each is skipped by decoding its
            // body exactly as sing-box would, so the cursor lands on the next item's tag.
            ITEM_QUERY_TYPE => {
                skip_base_slice(r, 2)?; // []uint16
            }
            ITEM_SOURCE_PORT | ITEM_PORT => {
                skip_base_slice(r, 2)?; // []uint16
            }
            ITEM_NETWORK_TYPE => {
                skip_base_slice(r, 1)?; // []uint8 (InterfaceType)
            }
            ITEM_NETWORK
            | ITEM_DOMAIN_REGEX
            | ITEM_SOURCE_PORT_RANGE
            | ITEM_PORT_RANGE
            | ITEM_PROCESS_NAME
            | ITEM_PROCESS_PATH
            | ITEM_PROCESS_PATH_REGEX
            | ITEM_PACKAGE_NAME
            | ITEM_WIFI_SSID
            | ITEM_WIFI_BSSID => {
                read_string_list(r)?; // []string, discarded
            }
            ITEM_ADGUARD_DOMAIN => read_adguard_domain(r)?,
            // Flag-only items carry no body.
            ITEM_NETWORK_IS_EXPENSIVE | ITEM_NETWORK_IS_CONSTRAINED => {}
            ITEM_FINAL => {
                let _invert = r.u8()?; // bool
                return Ok(());
            }
            _ => return Err(SrsError::Malformed("unknown rule item type")),
        }
    }
}

/// Read a `[]string` (uvarint count, then each string is a uvarint-len + UTF-8 body).
fn read_string_list<'a>(r: &mut Reader<'a>) -> Result<Vec<&'a str>, SrsError> {
    let n = r.uvarint_usize()?;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(r.string()?);
    }
    Ok(v)
}

/// Skip a `varbin` base slice: uvarint count, then `count * item_size` fixed-width bytes.
fn skip_base_slice(r: &mut Reader, item_size: usize) -> Result<(), SrsError> {
    let n = r.uvarint_usize()?;
    let total = n.checked_mul(item_size).ok_or(SrsError::Truncated)?;
    r.bytes(total)?;
    Ok(())
}

/// Read a `[]uint64` (uvarint count, then `count` big-endian `u64`s) — the succinct-set bit arrays.
fn read_u64_slice(r: &mut Reader) -> Result<Vec<u64>, SrsError> {
    let n = r.uvarint_usize()?;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(r.u64_be()?);
    }
    Ok(v)
}

// ---------------------------------------------------------------------------------------------
// Domain item: sing's succinct domain set (`sing/common/domain/{set,matcher}.go`).
// ---------------------------------------------------------------------------------------------

/// Read the `ruleItemDomain` body: a `succinctSetData` struct
/// `{ Reserved u8, Leaves []u64, LabelBitmap []u64, Labels []u8 }`, decode the reversed-domain
/// keys, then split them into exact `domain` vs `domain_suffix` the way sing's `Matcher.Dump` does.
fn read_domain_item(r: &mut Reader, out: &mut RuleSet) -> Result<(), SrsError> {
    let _reserved = r.u8()?;
    let leaves = read_u64_slice(r)?;
    let label_bitmap = read_u64_slice(r)?;
    let labels_len = r.uvarint_usize()?;
    let labels = r.bytes(labels_len)?.to_vec();

    let set = SuccinctSet {
        leaves,
        label_bitmap,
        labels,
    };
    let keys = set.keys()?;
    dump_domains(keys, out);
    Ok(())
}

/// The three succinct arrays that encode the reversed-domain trie (`sing/common/domain/set.go`).
struct SuccinctSet {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
}

/// A precomputed rank/select index over a bitmap: O(1) rank (`ones`/`zeros`) and O(log words + 64)
/// select (`select_one`), built once. This replaces the succinct-set traversal's former per-call
/// linear scans, which made [`SuccinctSet::keys`] O(n²) — a large rule-set (e.g. BanAD) took seconds
/// to parse. `cum_ones[w]` is the number of 1-bits in `words[0..w]` (so `cum_ones.len() == words+1`).
struct BitRank<'a> {
    words: &'a [u64],
    cum_ones: Vec<usize>,
}

impl<'a> BitRank<'a> {
    fn new(words: &'a [u64]) -> Self {
        let mut cum_ones = Vec::with_capacity(words.len() + 1);
        let mut acc = 0usize;
        cum_ones.push(0);
        for w in words {
            acc += w.count_ones() as usize;
            cum_ones.push(acc);
        }
        Self { words, cum_ones }
    }

    /// Number of 1-bits in `[0, i)`.
    fn ones(&self, i: usize) -> usize {
        let word = i >> 6;
        if word >= self.words.len() {
            // At or beyond the last bit: every stored 1 is counted (bits past the bitmap are 0).
            return self.cum_ones.last().copied().unwrap_or(0);
        }
        let bit = i & 63;
        let partial = if bit == 0 {
            0
        } else {
            (self.words[word] & ((1u64 << bit) - 1)).count_ones() as usize
        };
        self.cum_ones[word] + partial
    }

    /// Number of 0-bits in `[0, i)` — the `countZeros` the traversal needs.
    fn zeros(&self, i: usize) -> usize {
        i - self.ones(i)
    }

    /// 0-based position of the `i`-th (0-based) set bit, or the bit length if absent (matching sing's
    /// `selectIthOne`). Binary-searches the word, then scans its 64 bits.
    fn select_one(&self, i: usize) -> usize {
        let total_bits = self.words.len() << 6;
        // The i-th one lives in word `p - 1`, where `p` = #(cum_ones entries ≤ i).
        let p = self.cum_ones.partition_point(|&c| c <= i);
        if p == 0 || p > self.words.len() {
            return total_bits; // the i-th one doesn't exist (word index p-1 out of range)
        }
        let widx = p - 1;
        let mut need = i - self.cum_ones[widx]; // rank within the word
        let w = self.words[widx];
        for bit in 0..64 {
            if (w >> bit) & 1 == 1 {
                if need == 0 {
                    return (widx << 6) + bit;
                }
                need -= 1;
            }
        }
        total_bits
    }
}

impl SuccinctSet {
    /// `getBit(bm, i)` — bit `i` of a `[]u64` little-endian-within-word bitmap.
    fn get_bit(bm: &[u64], i: usize) -> bool {
        match bm.get(i >> 6) {
            Some(w) => w & (1u64 << (i & 63)) != 0,
            None => false,
        }
    }

    /// Recover every reversed-domain key stored in the set — the port of `succinctSet.keys`
    /// (`sing/common/domain/set.go`), written iteratively so a pathological set can't blow the
    /// stack. Each key is the label path from the root to a leaf node.
    fn keys(&self) -> Result<Vec<Vec<u8>>, SrsError> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        // Rank/select index over the label bitmap, built once — the child lookups below are O(1)/
        // O(log) instead of the former per-edge linear scans (which made this O(n²)).
        let rank = BitRank::new(&self.label_bitmap);
        // Frame = (node_id, bm_idx, key-so-far). We push children to walk the trie depth-first,
        // exactly matching the recursive Go traversal's ordering of label edges.
        struct Frame {
            node_id: usize,
            bm_idx: usize,
            key: Vec<u8>,
        }
        let mut stack = vec![Frame {
            node_id: 0,
            bm_idx: 0,
            key: Vec::new(),
        }];
        while let Some(Frame {
            node_id,
            mut bm_idx,
            key,
        }) = stack.pop()
        {
            if Self::get_bit(&self.leaves, node_id) {
                result.push(key.clone());
            }
            // Walk this node's outgoing label edges until the bitmap's separator 1-bit.
            loop {
                if Self::get_bit(&self.label_bitmap, bm_idx) {
                    break;
                }
                let label_idx = bm_idx
                    .checked_sub(node_id)
                    .ok_or(SrsError::Malformed("succinct set: label index underflow"))?;
                let next_label = *self
                    .labels
                    .get(label_idx)
                    .ok_or(SrsError::Malformed("succinct set: label out of range"))?;
                let next_node_id = rank.zeros(bm_idx + 1);
                if next_node_id == 0 {
                    return Err(SrsError::Malformed("succinct set: node id underflow"));
                }
                let next_bm_idx = rank.select_one(next_node_id - 1) + 1;
                let mut child_key = key.clone();
                child_key.push(next_label);
                stack.push(Frame {
                    node_id: next_node_id,
                    bm_idx: next_bm_idx,
                    key: child_key,
                });
                bm_idx += 1;
            }
        }
        Ok(result)
    }
}

/// Reverse a domain byte-for-byte. sing reverses by UTF-8 rune, but every byte it stores is either a
/// single-byte sentinel (`\r`/`\n`) or an ASCII domain char, so byte reversal is exact here.
fn reverse_bytes(mut b: Vec<u8>) -> Vec<u8> {
    b.reverse();
    b
}

/// Split the recovered (reversed) keys into exact `domain` vs `domain_suffix`, porting sing's
/// `Matcher.Dump` (`sing/common/domain/matcher.go`): a `\r`-prefixed key is a `.`-anchored suffix, a
/// `\n`-prefixed key is a bare suffix, anything else is an exact domain — with the fold-in step that
/// promotes `.example.com` + `example.com` down to a single `example.com` suffix.
fn dump_domains(keys: Vec<Vec<u8>>, out: &mut RuleSet) {
    let mut domain_map: std::collections::BTreeSet<String> = Default::default();
    let mut prefix_set: std::collections::BTreeSet<String> = Default::default();
    let mut suffix_list: Vec<String> = Vec::new();

    for key in keys {
        let key = reverse_bytes(key);
        match key.first().copied() {
            Some(PREFIX_LABEL) => {
                if let Ok(s) = std::str::from_utf8(&key[1..]) {
                    prefix_set.insert(s.to_owned());
                }
            }
            Some(ROOT_LABEL) => {
                if let Ok(s) = std::str::from_utf8(&key[1..]) {
                    suffix_list.push(s.to_owned());
                }
            }
            _ => {
                if let Ok(s) = std::str::from_utf8(&key) {
                    domain_map.insert(s.to_owned());
                }
            }
        }
    }

    // sing folds a `\r`-prefix of the form `.root` back into a plain `root` suffix when the exact
    // `root` domain is also present, so `.example.com` + `example.com` collapse to one suffix.
    for raw_prefix in prefix_set {
        if let Some(root) = raw_prefix.strip_prefix('.') {
            if domain_map.remove(root) {
                suffix_list.push(root.to_owned());
                continue;
            }
        }
        suffix_list.push(raw_prefix);
    }

    out.domain.extend(domain_map);
    out.domain_suffix.extend(suffix_list);
}

// ---------------------------------------------------------------------------------------------
// IPCIDR item: sing-box's IP-set (`common/srs/ip_set.go`) — a version byte, a raw u64 range count,
// then `[]{From []byte, To []byte}` address pairs, each range expanded to covering prefixes.
// ---------------------------------------------------------------------------------------------

/// Read the `ruleItemIPCIDR` body and expand every stored `[from, to]` range into CIDR prefixes.
fn read_ip_set(r: &mut Reader) -> Result<Vec<IpCidr>, SrsError> {
    let version = r.u8()?;
    if version != 1 {
        return Err(SrsError::Malformed("ip set: unsupported version"));
    }
    // The range count is a *fixed* big-endian u64 (not a uvarint) — see the "WTF why using uint64
    // here" note in sing-box's ip_set.go. The `ranges` slice is then pre-sized to this length, so
    // the following struct reads carry no further length prefix.
    let count = usize::try_from(r.u64_be()?).map_err(|_| SrsError::Malformed("ip set: count"))?;
    let mut out = Vec::new();
    for _ in 0..count {
        let from = read_ip_bytes(r)?;
        let to = read_ip_bytes(r)?;
        append_range_prefixes(from, to, &mut out)?;
    }
    Ok(out)
}

/// Read one `[]byte` IP field (uvarint len + bytes) into an [`IpAddr`]; 4 bytes ⇒ v4, 16 ⇒ v6.
fn read_ip_bytes(r: &mut Reader) -> Result<IpAddr, SrsError> {
    let len = r.uvarint_usize()?;
    let b = r.bytes(len)?;
    match len {
        4 => Ok(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            Ok(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ => Err(SrsError::Malformed("ip set: bad address length")),
    }
}

/// Expand an inclusive `[from, to]` address range into the minimal set of covering CIDR prefixes.
/// Both bounds must be the same family. Ports `netipx`'s `appendRangePrefixes`, done on a `u128`
/// with the IPv4 range operated on in its low 32 bits.
fn append_range_prefixes(from: IpAddr, to: IpAddr, out: &mut Vec<IpCidr>) -> Result<(), SrsError> {
    match (from, to) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            append_range_u32(u32::from(a), u32::from(b), out);
            Ok(())
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            append_range_u128(u128::from(a), u128::from(b), out);
            Ok(())
        }
        _ => Err(SrsError::Malformed("ip set: mixed-family range")),
    }
}

/// IPv4 range → prefixes, over a `u32` (bit width 32).
fn append_range_u32(mut a: u32, b: u32, out: &mut Vec<IpCidr>) {
    loop {
        let common = (a ^ b).leading_zeros().min(32) as u8;
        // A range whose bits after `common` are all-zero in `a` and all-one in `b` is one prefix.
        let host_bits = 32 - common as u32;
        let host_mask = if host_bits == 32 {
            u32::MAX
        } else {
            (1u32 << host_bits) - 1
        };
        if a & host_mask == 0 && b & host_mask == host_mask {
            out.push(IpCidr {
                addr: IpAddr::V4(Ipv4Addr::from(a)),
                prefix: common,
            });
            return;
        }
        // Otherwise split: lower half is [a, a with bits set from common+1]; recurse on the rest.
        let split_bits = 32 - (common as u32 + 1);
        let split_mask = if split_bits >= 32 {
            u32::MAX
        } else {
            (1u32 << split_bits) - 1
        };
        let a_high = a | split_mask; // a with all bits from common+1 set to one
        append_range_u32(a, a_high, out);
        a = a_high.wrapping_add(1); // b_low = b with bits from common+1 cleared == a_high + 1
    }
}

/// IPv6 range → prefixes, over a `u128` (bit width 128).
fn append_range_u128(mut a: u128, b: u128, out: &mut Vec<IpCidr>) {
    loop {
        let common = (a ^ b).leading_zeros().min(128) as u8;
        let host_bits = 128 - common as u32;
        let host_mask = if host_bits == 128 {
            u128::MAX
        } else {
            (1u128 << host_bits) - 1
        };
        if a & host_mask == 0 && b & host_mask == host_mask {
            out.push(IpCidr {
                addr: IpAddr::V6(Ipv6Addr::from(a)),
                prefix: common,
            });
            return;
        }
        let split_bits = 128 - (common as u32 + 1);
        let split_mask = if split_bits >= 128 {
            u128::MAX
        } else {
            (1u128 << split_bits) - 1
        };
        let a_high = a | split_mask;
        append_range_u128(a, a_high, out);
        a = a_high.wrapping_add(1);
    }
}

/// Skip an AdGuard domain matcher (`ruleItemAdGuardDomain`, v2+): the config never uses it, but we
/// must consume its body — a `succinctSetData`-shaped struct, same field layout as the plain domain
/// set — so the cursor stays aligned. We decode-and-discard rather than interpret it.
fn read_adguard_domain(r: &mut Reader) -> Result<(), SrsError> {
    let _reserved = r.u8()?;
    let _leaves = read_u64_slice(r)?;
    let _label_bitmap = read_u64_slice(r)?;
    let labels_len = r.uvarint_usize()?;
    r.bytes(labels_len)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `cargo test` runs with the crate root (`core/`) as the working directory, so the fixtures
    /// (real rule-sets from the live config) resolve at `tests/fixtures/srs/`.
    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("tests/fixtures/srs/{name}.srs"))
            .unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
    }

    #[test]
    fn envelope_accepts_v1_v2_v3() {
        for (name, want_ver) in [("common_v3", 3u8), ("banad_v1", 1), ("category-ads_v2", 2)] {
            let env = decode_envelope(&fixture(name)).expect("decode envelope");
            assert_eq!(env.version, want_ver, "{name} version");
            assert!(!env.body.is_empty(), "{name}: decompressed body is empty");
        }
    }

    #[test]
    fn envelope_rejects_bad_magic_and_truncation() {
        assert!(matches!(
            decode_envelope(b"ZZZ\x01").unwrap_err(),
            SrsError::BadMagic
        ));
        assert!(matches!(
            decode_envelope(b"SR").unwrap_err(),
            SrsError::Truncated
        ));
        assert!(matches!(
            decode_envelope(b"SRS\x09").unwrap_err(),
            SrsError::UnsupportedVersion(9)
        ));
    }

    #[test]
    fn reader_uvarint_string_and_exhaustion() {
        let mut r = Reader::new(&[0xbb, 0x01, 0x03, b'a', b'b', b'c']);
        assert_eq!(r.uvarint().unwrap(), 187); // 0xbb,0x01 = 59 + (1<<7)
        assert_eq!(r.string().unwrap(), "abc"); // len 3 + "abc"
        assert!(matches!(r.uvarint().unwrap_err(), SrsError::Truncated)); // exhausted
    }

    #[test]
    fn reader_rejects_short_read_and_bad_utf8() {
        // length prefix says 2 but only 1 byte follows → Truncated
        assert!(matches!(
            Reader::new(&[0x02, b'x']).string().unwrap_err(),
            SrsError::Truncated
        ));
        // valid length, invalid UTF-8 → Malformed
        assert!(matches!(
            Reader::new(&[0x01, 0xff]).string().unwrap_err(),
            SrsError::Malformed(_)
        ));
    }

    /// Read the oracle CSV rows of a given `rule type` into a sorted set of values.
    fn oracle(rule_type: &str) -> std::collections::BTreeSet<String> {
        let csv = std::fs::read_to_string("tests/fixtures/srs/expected/common_v3.csv")
            .expect("read oracle csv");
        csv.lines()
            .skip(1) // header: "rule type,value"
            .filter_map(|line| line.split_once(','))
            .filter(|(ty, _)| *ty == rule_type)
            .map(|(_, val)| val.to_owned())
            .collect()
    }

    /// The hard proof: v3 `common.srs`'s decoded exact-`domain` and `domain_suffix` sets must equal
    /// the exact source rows that compiled to it.
    #[test]
    fn parse_common_v3_matches_oracle() {
        let rs = parse(&fixture("common_v3")).expect("parse common_v3");

        let got_suffix: std::collections::BTreeSet<String> =
            rs.domain_suffix.iter().cloned().collect();
        let got_domain: std::collections::BTreeSet<String> = rs.domain.iter().cloned().collect();
        let want_suffix = oracle("domain_suffix");
        let want_domain = oracle("domain");

        assert_eq!(
            got_suffix.len(),
            want_suffix.len(),
            "domain_suffix count: got {}, want {}",
            got_suffix.len(),
            want_suffix.len()
        );
        assert_eq!(got_suffix, want_suffix, "domain_suffix set mismatch");
        assert_eq!(
            got_domain,
            want_domain,
            "domain set mismatch (got {} / want {})",
            got_domain.len(),
            want_domain.len()
        );
    }

    /// True if `rs` matches `domain` — either exactly, or via a suffix entry that covers it
    /// (`example.com` covers `example.com` and `*.example.com`).
    fn contains_or_suffix(rs: &RuleSet, domain: &str) -> bool {
        if rs.domain.iter().any(|d| d == domain) {
            return true;
        }
        // Label-boundary suffix match only: `discord.com` covers `discord.com` and `*.discord.com`,
        // but NOT `notdiscord.com` (a bare `ends_with(s)` would wrongly match that).
        rs.domain_suffix
            .iter()
            .any(|s| domain == s || domain.ends_with(&format!(".{s}")))
    }

    /// v1 + v2 spot-check: both ad lists decode to hundreds of domains, and known ad domains match.
    #[test]
    fn parse_v1_v2_ad_lists_have_real_domains() {
        let banad = parse(&fixture("banad_v1")).expect("parse banad_v1");
        let cat_ads = parse(&fixture("category-ads_v2")).expect("parse category-ads_v2");

        let banad_total = banad.domain.len() + banad.domain_suffix.len();
        let cat_total = cat_ads.domain.len() + cat_ads.domain_suffix.len();
        assert!(
            banad_total >= 100,
            "banad_v1: expected hundreds of domains, got {banad_total}"
        );
        assert!(
            cat_total >= 100,
            "category-ads_v2: expected hundreds of domains, got {cat_total}"
        );

        // Well-known ad domains must be matched by at least one of the two lists.
        for probe in ["doubleclick.net", "googlesyndication.com"] {
            assert!(
                contains_or_suffix(&banad, probe) || contains_or_suffix(&cat_ads, probe),
                "neither ad list matches {probe}"
            );
        }
    }

    /// The `IpCidr` Display renders standard CIDR notation for both families.
    #[test]
    fn ip_cidr_display() {
        let v4 = IpCidr {
            addr: "1.2.3.0".parse().unwrap(),
            prefix: 24,
        };
        assert_eq!(v4.to_string(), "1.2.3.0/24");
        let v6 = IpCidr {
            addr: "2001:db8::".parse().unwrap(),
            prefix: 32,
        };
        assert_eq!(v6.to_string(), "2001:db8::/32");
    }

    /// The netipx range→prefix port: a whole /24 collapses to one prefix; an off-boundary range
    /// splits into the minimal covering set.
    #[test]
    fn range_to_prefixes_v4() {
        let mut out = Vec::new();
        append_range_u32(
            u32::from("10.50.0.0".parse::<Ipv4Addr>().unwrap()),
            u32::from("10.50.255.255".parse::<Ipv4Addr>().unwrap()),
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].to_string(), "10.50.0.0/16");

        out.clear();
        // 192.168.0.0 .. 192.168.0.5  →  /29 (0-7 too wide) must split into .0/30 + .4/31.
        append_range_u32(
            u32::from("192.168.0.0".parse::<Ipv4Addr>().unwrap()),
            u32::from("192.168.0.5".parse::<Ipv4Addr>().unwrap()),
            &mut out,
        );
        let rendered: Vec<String> = out.iter().map(IpCidr::to_string).collect();
        assert_eq!(rendered, ["192.168.0.0/30", "192.168.0.4/31"]);
    }

    /// The rank/select index matches a naive scan across word boundaries and empty words — the math
    /// the O(n²)→O(n log n) succinct-set speedup relies on.
    #[test]
    fn bit_rank_matches_naive_rank_and_select() {
        let words = vec![0b1010u64, 0, (1u64 << 63) | 1, u64::MAX];
        let rank = BitRank::new(&words);
        let total_bits = words.len() * 64;
        let bit = |i: usize| (words[i >> 6] >> (i & 63)) & 1 == 1;

        for i in 0..=total_bits {
            let naive_ones = (0..i).filter(|&j| bit(j)).count();
            assert_eq!(rank.ones(i), naive_ones, "ones({i})");
            assert_eq!(rank.zeros(i), i - naive_ones, "zeros({i})");
        }
        let ones: Vec<usize> = (0..total_bits).filter(|&j| bit(j)).collect();
        for (i, &pos) in ones.iter().enumerate() {
            assert_eq!(rank.select_one(i), pos, "select_one({i})");
        }
        // An out-of-range one index returns the bit length (matching sing's selectIthOne).
        assert_eq!(rank.select_one(ones.len()), total_bits);
    }

    /// Negative: a truncated body and an unknown item tag both error rather than panic.
    #[test]
    fn parse_rejects_truncation_and_unknown_item() {
        // Truncated: a valid envelope whose body claims a rule but supplies nothing.
        let truncated = build_srs(3, &[0x01]); // rule count = 1, but no rule bytes follow
        assert!(parse(&truncated).is_err());

        // Unknown item tag: default rule (type 0) then item tag 0x7e (undefined) → Malformed.
        let unknown = build_srs(3, &[0x01, RULE_TYPE_DEFAULT, 0x7e]);
        assert!(matches!(
            parse(&unknown).unwrap_err(),
            SrsError::Malformed(_)
        ));

        // A hard-truncated envelope (magic+version only, no zlib) errors, never panics.
        assert!(parse(b"SRS\x03").is_err());
    }

    #[test]
    fn parse_geoip_exercises_ip_set_end_to_end() {
        // A real IP-based rule-set (KaringX geoip/malware, v1) drives read_ip_set against real
        // bytes — the domain fixtures carry no ip_cidr, so without this the IP path is only
        // synthetically covered (see `range_to_prefixes_v4`).
        let rs = parse(&fixture("geoip-malware")).expect("parse geoip-malware");
        assert!(
            rs.ip_cidr.len() >= 10,
            "expected many CIDRs from a geoip malware list, got {}",
            rs.ip_cidr.len()
        );
        // Every entry renders as addr/prefix with a sane prefix width.
        for c in &rs.ip_cidr {
            let s = c.to_string();
            assert!(s.contains('/'), "cidr renders with a prefix: {s}");
            let max = if c.addr.is_ipv4() { 32 } else { 128 };
            assert!(c.prefix <= max, "prefix {} exceeds {max}", c.prefix);
        }
        // A pure geoip set has no domain entries.
        assert!(rs.domain.is_empty() && rs.domain_suffix.is_empty());
    }

    #[test]
    fn parse_ip_or_cidr_accepts_bare_ip_and_cidr() {
        assert_eq!(parse_ip_or_cidr("1.2.3.4").unwrap().prefix, 32);
        assert_eq!(parse_ip_or_cidr("10.0.0.0/8").unwrap().prefix, 8);
        assert_eq!(parse_ip_or_cidr("::1").unwrap().prefix, 128);
        assert_eq!(parse_ip_or_cidr("2001:db8::/32").unwrap().prefix, 32);
        assert!(parse_ip_or_cidr("nope").is_none());
        assert!(parse_ip_or_cidr("1.2.3.4/40").is_none()); // out of range
    }

    #[test]
    fn from_domains_and_ips_fills_suffix_and_cidr() {
        let rs =
            RuleSet::from_domains_and_ips(&["google.com".to_string()], &["1.2.3.4".to_string()]);
        assert_eq!(rs.domain_suffix, vec!["google.com".to_string()]);
        assert_eq!(rs.ip_cidr.len(), 1);
        assert!(rs.domain.is_empty() && rs.domain_keyword.is_empty());

        // Unparseable IP entries are silently dropped.
        let rs2 = RuleSet::from_domains_and_ips(&[], &["not-an-ip".to_string()]);
        assert!(rs2.ip_cidr.is_empty());
    }

    /// Wrap a plaintext rule body in the `.srs` envelope (magic + version + zlib) for tests.
    fn build_srs(version: u8, plain_body: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut zlib = Vec::new();
        let mut enc = flate2::write::ZlibEncoder::new(&mut zlib, flate2::Compression::default());
        enc.write_all(plain_body).expect("zlib write");
        enc.finish().expect("zlib finish");
        let mut out = Vec::with_capacity(4 + zlib.len());
        out.extend_from_slice(b"SRS");
        out.push(version);
        out.extend_from_slice(&zlib);
        out
    }
}
