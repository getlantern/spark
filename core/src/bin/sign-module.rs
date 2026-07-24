//! `sign-module` — offline signing tool for dynamic-transport modules (ADR 0013 §7 step 4).
//!
//! The one place a private module-signing key is used. Compiled only under the off-by-default
//! `module-signer` feature, so it never enters a shipped binary. Four subcommands:
//!
//! ```text
//! sign-module sign   --name <NAME> --version <U32> --wasm <IN.wasm> --out <OUT.spkw> (--dev | --key-pkcs8 <KEY.pkcs8>)
//! sign-module keygen --out <KEY.pkcs8>                  # mint a production signing key; prints its pubkey hex
//! sign-module pubkey (--dev | --key-pkcs8 <KEY.pkcs8>)  # print a key's pubkey hex (for SPARK_MODULE_PUBKEY_HEX)
//! sign-module verify <IN.spkw> --pubkey-hex <HEX>      # verify a signed artifact against a pinned pubkey
//! ```
//!
//! `verify` is the only subcommand that needs no private key — it re-runs the exact client-side check
//! (`ModuleVerifier::verify`) against a given pubkey hex, so an operator can confirm a `.spkw` validates
//! under the key clients pin before distributing it (runbook step C).
//!
//! `--dev` uses the repo's development keypair (which `ModuleVerifier::pinned()` accepts in a debug
//! build); `--key-pkcs8 <path>` uses a real Ed25519 PKCS#8 key for a production artifact. The typical
//! production flow: `keygen` a key into secret storage, pin its `SPARK_MODULE_PUBKEY_HEX` into the
//! client build, and `sign --key-pkcs8` each module with it.

use std::process::ExitCode;

use ring::signature::Ed25519KeyPair;
use spark_core::transport::wasm::{
    dev_keypair, generate_keypair_pkcs8, public_key_hex, sign_artifact, ModuleVerifier,
};

const USAGE: &str = "usage:\n  \
sign-module sign   --name <NAME> --version <U32> --wasm <IN.wasm> --out <OUT.spkw> (--dev | --key-pkcs8 <KEY.pkcs8>)\n  \
sign-module keygen --out <KEY.pkcs8>\n  \
sign-module pubkey (--dev | --key-pkcs8 <KEY.pkcs8>)\n  \
sign-module verify <IN.spkw> --pubkey-hex <HEX>";

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
        Some("keygen") => keygen(args),
        Some("pubkey") => pubkey(args),
        Some("verify") => verify(args),
        Some(other) => Err(format!("unknown subcommand: {other}")),
        None => Err("missing subcommand (sign | keygen | pubkey | verify)".into()),
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
    // Create the output directory so a fresh checkout (or a new module's fixture dir) just works.
    if let Some(parent) = std::path::Path::new(&out_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    std::fs::write(&out_path, &artifact).map_err(|e| format!("writing {out_path}: {e}"))?;
    eprintln!(
        "signed '{name}' v{version}: {} bytes wasm -> {} bytes artifact -> {out_path}",
        wasm.len(),
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

fn verify(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let (mut spkw_path, mut pubkey_hex) = (None, None);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--pubkey-hex" => pubkey_hex = Some(next_value(&mut args, &arg)?),
            s if !s.starts_with("--") && spkw_path.is_none() => spkw_path = Some(s.to_string()),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let spkw_path = spkw_path.ok_or("a <spkw> path is required")?;
    let pubkey = pubkey_from_hex(&pubkey_hex.ok_or("--pubkey-hex is required")?)?;

    let artifact = std::fs::read(&spkw_path).map_err(|e| format!("reading {spkw_path}: {e}"))?;
    // Re-run the exact client-side check. min_version 0 = accept any module version: this proves the
    // signature validates under the given key, not that it clears a rollout floor (a separate axis).
    let signed = ModuleVerifier::new(pubkey)
        .verify(&artifact, 0)
        .map_err(|e| format!("verification FAILED for {spkw_path}: {e}"))?;
    eprintln!(
        "OK: '{}' v{} verifies under the given pubkey ({} bytes)",
        signed.name(),
        signed.version(),
        artifact.len()
    );
    Ok(())
}
