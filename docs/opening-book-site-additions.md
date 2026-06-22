# Opening Book — site additions (draft)

Draft prose to port into the public site (`getlantern/opening-book`, not checked out here). It
deepens three things the live site states briefly: **what a gambit can actually say**, the
**well-formed vs. byte-level** split, and **where the move ends**. Written to match the site's voice
(terse, declarative, chess-themed). Slot these in after the existing `♜03 — A gambit is data`.

---

## ♟ — the move's vocabulary

A gambit speaks in three layers, each a set of deltas over the genuine-Chrome anchor.

**The hello (what's in it).** Which extensions, in which order — reproduced from a seed so it's
Chrome's own per-connection shuffle, not a tell. Whether to GREASE, and with what seed. Whether to
pad the hello to a chosen length. Whether to offer post-quantum key exchange. ECH: off, greased, or
real. ALPS on or off. The session id: fresh, resumed, or — for the byte-level class — chosen.

**The frame (how it's cut).** A record-size limit. Where the hello is split across TLS records, so a
matcher that reads only the first record never sees the name.

**The wire (how it lands).** Where the byte stream splits across TCP segments — at the hostname
boundary, say — and how long to wait between them. Whether each segment leaves as its own packet.

> One integer can be the whole move: bump a permutation seed and the hello is a different-but-valid
> Chrome. That's what makes the search cheap — and what makes a winning move shippable as a few signed
> bytes.

## ♝ — well-formed, or byte-level

Most moves stay **well-formed**: a different, still-valid Chrome. They run on either engine, today,
and the TLS library stays in charge — so the handshake still completes against a real server. This is
the default, and it covers most of what a censor reacts to.

A tagged minority reach for **byte-level** tricks — an exact hello written byte by byte, a chosen
session id, a deliberate malformation that splits a parser. These need more than a well-formed hello
allows, so each carries a capability tag. An engine that can't honor the tag declines the move and
falls back to its best portable one — **a bold move never costs a connection.** Byte-level moves are
reviewed before they ship.

So the repertoire an engine can play is narrower than the repertoire the genome can *write*: the
lean Rust engine plays the well-formed moves and the timing/framing layers today; the full
byte-level vocabulary lights up on the Go engine and, later, on a dedicated byte-builder. The genome
is the same on both — only the reach differs.

## ⚐ — where the move ends

A gambit shapes the **opening, and only the opening** — the hello, its records, the first few
segments. After the handshake completes, the gambit is silent: the rest of the connection runs as the
transport sees fit.

That's the wager. A modern censor files its verdict on the first few hundred bytes; if the opening
passes, the opening was the game. Shaping the long tail of a connection is expensive and high-volume,
and the opening is cheap — a few hundred bytes, once. So the book is opening theory: it spends its
moves where the verdict is made, and leaves the middlegame to the transport.

The door to the middlegame is left ajar — the genome reserves room for post-opening moves, unused
for now — for the day a censor learns to read past the opening.
