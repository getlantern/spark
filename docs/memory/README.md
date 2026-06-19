# Session memory (handoff snapshot)

These are the cross-session **memory notes** Claude Code accumulated while building spark — durable
facts, decisions, and gotchas that aren't obvious from the code or git history. They normally live
*outside* the repo (in `~/.claude/projects/<this-project>/memory/`), where a Claude session recalls
them automatically. This is a **checked-in snapshot** so the context survives a fresh clone / a
different machine / a handoff to another session.

- **[MEMORY.md](MEMORY.md)** — the index (one line per memory).
- Each `*.md` is one memory: `name` + `description` + `metadata` frontmatter, then the fact. Notes
  link to each other with `[[name]]`.

**To rehydrate native recall** on a machine that doesn't have them, copy these back into that
machine's memory dir:

```
cp docs/memory/*.md ~/.claude/projects/-Users-afisk-go-src-github-com-getlantern-spark/memory/
```

(Adjust the slug if the repo lives at a different path — the dir name is the project path with `/`
→ `-`.) The authoritative current-state handoff is **`docs/STATE.md` → "Current position"**; these
memories are the supporting detail.
