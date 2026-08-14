//! `sign-module` — offline signing tool for dynamic-transport modules (ADR 0013 §7 step 4).
//!
//! The one place a private module-signing key is used. Compiled only under the off-by-default
//! `module-signer` feature, so it never enters a shipped binary. Five subcommands:
//!
//! ```text
//! sign-module sign   --name <NAME> --version <U32> --wasm <IN.wasm> --out <OUT.spkw> (--dev | --key-pkcs8 <KEY.pkcs8>)
//! sign-module bundle --engine <NAME> --version <U32> --out <OUT.spkb> [--wasm <IN.wasm>] …
//! sign-module keygen --out <KEY.pkcs8>                  # mint a production signing key; prints its pubkey hex
//! sign-module pubkey (--dev | --key-pkcs8 <KEY.pkcs8>)  # print a key's pubkey hex (for SPARK_MODULE_PUBKEY_HEX)
//! sign-module verify <IN.spkw|IN.spkb> --pubkey-hex <HEX>  # verify either artifact against a pinned pubkey
//! ```
//!
//! `sign` produces a bare `.spkw` **module**; `bundle` produces a `.spkb` **bundle** — an engine name,
//! its opening plans, an optional module, and a capability grant, all signed together. Delivery over
//! the config channel uses bundles, because only a bundle gets the store's persisted anti-rollback
//! floors and carries the capability scoping inside the signature
//! (`docs/module-distribution-and-trust-design.md` Part A). `.spkw` remains the form the local
//! `transport.wasm.module` path and the AnyTLS gambit module consume.
//!
//! `verify` is the only subcommand that needs no private key — it re-runs the exact client-side check
//! against a given pubkey hex, so an operator can confirm an artifact validates under the key clients
//! pin before distributing it (runbook step C). It dispatches on the artifact's magic, so the same
//! invocation checks either form.
//!
//! `--dev` uses the repo's development keypair (which `ModuleVerifier::pinned()` accepts in a debug
//! build); `--key-pkcs8 <path>` uses a real Ed25519 PKCS#8 key for a production artifact. The typical
//! production flow: `keygen` a key into secret storage, pin its `SPARK_MODULE_PUBKEY_HEX` into the
//! client build, and `sign`/`bundle --key-pkcs8` each artifact with it.

use std::process::ExitCode;

use ring::signature::Ed25519KeyPair;
use spark_core::transport::engine::{sign_bundle, Bundle, BundleVerifier, Genome};
use spark_core::transport::wasm::{
    dev_keypair, generate_keypair_pkcs8, public_key_hex, sign_artifact, ModuleVerifier,
};

const USAGE: &str = "usage:\n  \
sign-module sign   --name <NAME> --version <U32> --wasm <IN.wasm> --out <OUT.spkw> (--dev | --key-pkcs8 <KEY.pkcs8>)\n  \
sign-module bundle --engine <NAME> --version <U32> --out <OUT.spkb> (--dev | --key-pkcs8 <KEY.pkcs8>)\n         \
[--wasm <IN.wasm>] [--capability <NAME>]... [--genome <IN.genome>]...\n         \
[--genome-id <ID>] [--genome-version <U64>] [--engine-params <HEX>]\n  \
sign-module keygen --out <KEY.pkcs8>\n  \
sign-module pubkey (--dev | --key-pkcs8 <KEY.pkcs8>)\n  \
sign-module verify <IN.spkw|IN.spkb> --pubkey-hex <HEX>";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sign-module: {e}\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("sign") => sign(args),
        Some("bundle") => bundle(args),
        Some("keygen") => keygen(args),
        Some("pubkey") => pubkey(args),
        Some("verify") => verify(args),
        Some(other) => Err(format!("unknown subcommand: {other}")),
        None => Err("missing subcommand (sign | bundle | keygen | pubkey | verify)".into()),
    }
}

/// Consume the next argument as `flag`'s value, or report it missing.
fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

/// Resolve the signing keypair from `--dev` / `--key-pkcs8`, rejecting neither-or-both.
fn load_keypair(dev: bool, key_path: Option<String>) -> Result<Ed25519KeyPair, String> {
    match (dev, key_path) {
        (true, None) => Ok(dev_keypair()),
        (false, Some(path)) => {
            let pkcs8 = std::fs::read(&path).map_err(|e| format!("reading {path}: {e}"))?;
            Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|e| format!("parsing key {path}: {e}"))
        }
        (true, Some(_)) => Err("pass either --dev or --key-pkcs8, not both".into()),
        (false, None) => Err("one of --dev or --key-pkcs8 is required".into()),
    }
}

fn sign(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let (mut name, mut version, mut wasm_path, mut out_path) = (None, None, None, None);
    let (mut dev, mut key_path) = (false, None);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--name" => name = Some(next_value(&mut args, &arg)?),
            "--version" => {
                let v = next_value(&mut args, &arg)?;
                version = Some(v.parse::<u32>().map_err(|e| format!("--version: {e}"))?);
            }
            "--wasm" => wasm_path = Some(next_value(&mut args, &arg)?),
            "--out" => out_path = Some(next_value(&mut args, &arg)?),
            "--key-pkcs8" => key_path = Some(next_value(&mut args, &arg)?),
            "--dev" => dev = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let name = name.ok_or("--name is required")?;
    let version = version.ok_or("--version is required")?;
    let wasm_path = wasm_path.ok_or("--wasm is required")?;
    let out_path = out_path.ok_or("--out is required")?;
    let keypair = load_keypair(dev, key_path)?;

    let wasm = std::fs::read(&wasm_path).map_err(|e| format!("reading {wasm_path}: {e}"))?;
    let artifact = sign_artifact(&keypair, &name, version, &wasm);
    write_out(&out_path, &artifact)?;
    eprintln!(
        "signed '{name}' v{version}: {} bytes wasm -> {} bytes artifact -> {out_path}",
        wasm.len(),
        artifact.len()
    );
    Ok(())
}

/// Write `bytes` to `path`, creating the parent directory so a fresh checkout (or a new module's
/// fixture/dist dir) just works.
fn write_out(path: &str, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = std::path::Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    std::fs::write(path, bytes).map_err(|e| format!("writing {path}: {e}"))
}

/// Decode an even-length ASCII hex string into bytes. Empty input yields an empty vec.
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.trim().as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(format!(
            "expected an even number of hex characters, got {}",
            bytes.len()
        ));
    }
    bytes
        .chunks_exact(2)
        .map(|pair| {
            let hex = std::str::from_utf8(pair).map_err(|_| "invalid hex".to_string())?;
            u8::from_str_radix(hex, 16).map_err(|e| format!("invalid hex: {e}"))
        })
        .collect()
}

/// Build and sign a `.spkb` **bundle** — the artifact the delivery path installs.
///
/// A bundle signs the engine name, its opening plans, an optional module, and the capability grant
/// *together*, which is what closes the gap where arbitrary WASM was authenticated but the genome
/// telling it what protocol to speak was not (see `engine/bundle.rs`).
///
/// Genomes come from either source, and both may be used at once:
///   * `--genome <FILE>` (repeatable) — a postcard-encoded [`Genome`], the form discovery produces.
///   * `--genome-id <ID>` — construct one here from `--genome-version` (default 1) and
///     `--engine-params <HEX>` (default empty), with a default wire plan.
///
/// `--capability` (repeatable) scopes the module's host imports; **absent means unrestricted**, which
/// is what a first-party bundle reasonably uses. The deny-everything grant (an explicitly empty list)
/// is deliberately not expressible here: it is reachable in code for tests, but a module that imports
/// anything at all simply fails to instantiate under it, so offering it as a flag would only be a
/// footgun.
///
/// The artifact is **verified against the signing key's own public half before it is written**. That
/// makes every authoring mistake this tool can make — an engine/name mismatch, an undecodable or
/// misaddressed genome, a schema drift — fail here, while the key is already out, rather than after
/// distribution.
fn bundle(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let (mut engine, mut version, mut out_path, mut wasm_path) = (None, None, None, None);
    let (mut dev, mut key_path) = (false, None);
    let (mut capabilities, mut genome_paths): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    let (mut genome_id, mut genome_version, mut engine_params) = (None, None, None);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--engine" => engine = Some(next_value(&mut args, &arg)?),
            "--version" => {
                let v = next_value(&mut args, &arg)?;
                version = Some(v.parse::<u32>().map_err(|e| format!("--version: {e}"))?);
            }
            "--out" => out_path = Some(next_value(&mut args, &arg)?),
            "--wasm" => wasm_path = Some(next_value(&mut args, &arg)?),
            "--capability" => capabilities.push(next_value(&mut args, &arg)?),
            "--genome" => genome_paths.push(next_value(&mut args, &arg)?),
            "--genome-id" => genome_id = Some(next_value(&mut args, &arg)?),
            "--genome-version" => {
                let v = next_value(&mut args, &arg)?;
                genome_version = Some(
                    v.parse::<u64>()
                        .map_err(|e| format!("--genome-version: {e}"))?,
                );
            }
            "--engine-params" => engine_params = Some(next_value(&mut args, &arg)?),
            "--key-pkcs8" => key_path = Some(next_value(&mut args, &arg)?),
            "--dev" => dev = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let engine = engine.ok_or("--engine is required")?;
    let version = version.ok_or("--version is required")?;
    let out_path = out_path.ok_or("--out is required")?;
    let keypair = load_keypair(dev, key_path)?;

    // Genome flags without an id are ambiguous — they'd silently apply to nothing.
    if genome_id.is_none() && (genome_version.is_some() || engine_params.is_some()) {
        return Err(
            "--genome-version / --engine-params describe a constructed genome, so --genome-id is required"
                .into(),
        );
    }

    let mut genomes: Vec<Vec<u8>> = Vec::new();
    for path in &genome_paths {
        let raw = std::fs::read(path).map_err(|e| format!("reading {path}: {e}"))?;
        // Decode to check it before signing it. A genome addressed to another engine is refused by
        // every client, so catching it here turns a distribution incident into an error message.
        let g = Genome::decode(&raw).map_err(|e| format!("{path} is not a valid genome: {e}"))?;
        if g.engine != engine {
            return Err(format!(
                "{path} is addressed to engine `{}`, not `{engine}`",
                g.engine
            ));
        }
        genomes.push(raw);
    }
    if let Some(id) = genome_id {
        let params = match &engine_params {
            Some(hex) => decode_hex(hex).map_err(|e| format!("--engine-params: {e}"))?,
            None => Vec::new(),
        };
        let mut g = Genome::new(id, &engine, Default::default(), params);
        if let Some(v) = genome_version {
            g.version = v;
        }
        genomes.push(g.encode().map_err(|e| format!("encoding genome: {e}"))?);
    }
    if genomes.is_empty() {
        return Err(
            "a bundle must carry at least one genome (--genome <FILE> or --genome-id <ID>)".into(),
        );
    }

    let wasm = match &wasm_path {
        Some(path) => Some(std::fs::read(path).map_err(|e| format!("reading {path}: {e}"))?),
        None => None,
    };
    let wasm_len = wasm.as_ref().map_or(0, Vec::len);
    let scoped = !capabilities.is_empty();
    let mut b = Bundle::new(&engine, genomes, wasm);
    if scoped {
        b = b.with_capabilities(capabilities.clone());
    }

    let artifact = sign_bundle(&keypair, &engine, version, &b)
        .map_err(|e| format!("signing bundle for `{engine}`: {e}"))?;

    // Self-verify with the public half of the very key that just signed, before anything is written.
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(ring::signature::KeyPair::public_key(&keypair).as_ref());
    let verified = BundleVerifier::new(pubkey)
        .verify(&artifact, 0, 0)
        .map_err(|e| format!("SELF-CHECK FAILED — refusing to write {out_path}: {e}"))?;

    write_out(&out_path, &artifact)?;
    eprintln!(
        "signed bundle '{engine}' v{version}: {} genome(s), {wasm_len} bytes wasm, capabilities {} \
         -> {} bytes artifact -> {out_path}",
        verified.genomes.len(),
        if scoped {
            capabilities.join(",")
        } else {
            "<unrestricted>".to_string()
        },
        artifact.len()
    );
    Ok(())
}

fn keygen(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let mut out_path = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => out_path = Some(next_value(&mut args, &arg)?),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let out_path = out_path.ok_or("--out is required")?;

    // Create the output directory so `--out some/dir/key.pkcs8` works (mirrors `sign`).
    if let Some(parent) = std::path::Path::new(&out_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }

    let pkcs8 = generate_keypair_pkcs8().map_err(|e| format!("generating keypair: {e}"))?;
    // Create the private key `0600` from the start (no create-then-chmod window where umask could leave
    // it group/world-readable) and refuse to clobber an existing key (`create_new`).
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&out_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            format!("{out_path} already exists — refusing to overwrite a signing key")
        } else {
            format!("creating {out_path}: {e}")
        }
    })?;
    std::io::Write::write_all(&mut file, &pkcs8).map_err(|e| format!("writing {out_path}: {e}"))?;
    #[cfg(not(unix))]
    eprintln!(
        "warning: {out_path} was NOT created with 0600 perms (non-unix); lock it down manually"
    );
    let keypair =
        Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|e| format!("parsing generated key: {e}"))?;
    let hex = public_key_hex(&keypair);
    eprintln!("wrote PRIVATE module-signing key -> {out_path} (keep secret; never commit; store in a vault)");
    eprintln!("pin this into the client build:  SPARK_MODULE_PUBKEY_HEX={hex}");
    // The pubkey hex on stdout, so it's scriptable: `KEY_HEX=$(sign-module keygen --out k.pkcs8)`.
    println!("{hex}");
    Ok(())
}

fn pubkey(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let (mut dev, mut key_path) = (false, None);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--key-pkcs8" => key_path = Some(next_value(&mut args, &arg)?),
            "--dev" => dev = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let keypair = load_keypair(dev, key_path)?;
    println!("{}", public_key_hex(&keypair));
    Ok(())
}

/// Decode a 64-char hex pubkey (as printed by `pubkey`/`keygen`) into the 32-byte array
/// `ModuleVerifier::new` expects.
fn pubkey_from_hex(s: &str) -> Result<[u8; 32], String> {
    // Decode over bytes, not chars: a multi-byte UTF-8 char could otherwise pass the length check and
    // then panic when `&s[2*i..2*i+2]` slices mid-codepoint. `chunks_exact(2)` never indexes past the end.
    let bytes = s.trim().as_bytes();
    if bytes.len() != 64 {
        return Err(format!(
            "--pubkey-hex must be 64 ASCII hex characters (32 bytes), got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let hex = std::str::from_utf8(pair).map_err(|_| "--pubkey-hex: invalid hex".to_string())?;
        *byte =
            u8::from_str_radix(hex, 16).map_err(|e| format!("--pubkey-hex: invalid hex: {e}"))?;
    }
    Ok(out)
}

/// Verify a signed artifact against a pinned pubkey, dispatching on its **magic** rather than its
/// filename — the two forms are distinguishable on the wire, and an operator renaming a file must not
/// change what gets checked.
fn verify(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let (mut path, mut pubkey_hex) = (None, None);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--pubkey-hex" => pubkey_hex = Some(next_value(&mut args, &arg)?),
            s if !s.starts_with("--") && path.is_none() => path = Some(s.to_string()),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let path = path.ok_or("a <spkw|spkb> path is required")?;
    let pubkey = pubkey_from_hex(&pubkey_hex.ok_or("--pubkey-hex is required")?)?;

    let artifact = std::fs::read(&path).map_err(|e| format!("reading {path}: {e}"))?;
    // Floors of 0 accept any version: this proves the signature validates under the given key, not
    // that the artifact clears a rollout floor (a separate axis, enforced by config and the store).
    match artifact.get(..4) {
        Some(b"SPKB") => {
            let v = BundleVerifier::new(pubkey)
                .verify(&artifact, 0, 0)
                .map_err(|e| format!("verification FAILED for {path}: {e}"))?;
            eprintln!(
                "OK: bundle '{}' v{} verifies under the given pubkey — {} genome(s), {}, \
                 capabilities {} ({} bytes)",
                v.engine,
                v.version,
                v.genomes.len(),
                match &v.wasm {
                    Some(w) => format!("{} bytes wasm", w.len()),
                    None => "plans only (no module)".to_string(),
                },
                match &v.capabilities {
                    Some(c) => c.join(","),
                    None => "<unrestricted>".to_string(),
                },
                artifact.len()
            );
        }
        // `SPKW` and anything else alike: a truncated or garbage file then reports the same error it
        // always did (`BadMagic` / `Truncated`), rather than a new "unrecognized magic" the runbook
        // doesn't mention.
        _ => {
            let signed = ModuleVerifier::new(pubkey)
                .verify(&artifact, 0)
                .map_err(|e| format!("verification FAILED for {path}: {e}"))?;
            eprintln!(
                "OK: module '{}' v{} verifies under the given pubkey ({} bytes)",
                signed.name(),
                signed.version(),
                artifact.len()
            );
        }
    }
    Ok(())
}
