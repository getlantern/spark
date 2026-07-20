//! `sign-module` — offline signer for dynamic-transport modules (ADR 0013 §7 step 4).
//!
//! Turns a compiled guest `.wasm` into a signed `.spkw` artifact that [`ModuleVerifier`] accepts. It
//! is the one place a private module-signing key is used. Invoked by `scripts/build-module.sh`;
//! compiled only under the off-by-default `module-signer` feature, so it never enters a shipped binary.
//!
//! ```text
//! sign-module --name <NAME> --version <U32> --wasm <IN.wasm> --out <OUT.spkw> (--dev | --key-pkcs8 <KEY>)
//! ```
//! `--dev` signs with the repo's development keypair (which `ModuleVerifier::pinned()` accepts in a
//! debug build); `--key-pkcs8 <path>` signs with a real Ed25519 PKCS#8 key for a production artifact.
//!
//! [`ModuleVerifier`]: spark_core::transport::wasm::ModuleVerifier

use std::process::ExitCode;

use ring::signature::Ed25519KeyPair;
use spark_core::transport::wasm::{dev_keypair, sign_artifact};

const USAGE: &str = "usage: sign-module --name <NAME> --version <U32> --wasm <IN.wasm> \
--out <OUT.spkw> (--dev | --key-pkcs8 <KEY.pkcs8>)";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sign-module: {e}\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

/// Consume the next argument as `flag`'s value, or report it missing.
fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn run() -> Result<(), String> {
    let mut name = None;
    let mut version = None;
    let mut wasm_path = None;
    let mut out_path = None;
    let mut dev = false;
    let mut key_path = None;

    let mut args = std::env::args().skip(1);
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

    let keypair = match (dev, key_path) {
        (true, None) => dev_keypair(),
        (false, Some(path)) => {
            let pkcs8 = std::fs::read(&path).map_err(|e| format!("reading {path}: {e}"))?;
            Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|e| format!("parsing key {path}: {e}"))?
        }
        (true, Some(_)) => return Err("pass either --dev or --key-pkcs8, not both".into()),
        (false, None) => return Err("one of --dev or --key-pkcs8 is required".into()),
    };

    let wasm = std::fs::read(&wasm_path).map_err(|e| format!("reading {wasm_path}: {e}"))?;
    let artifact = sign_artifact(&keypair, &name, version, &wasm);
    std::fs::write(&out_path, &artifact).map_err(|e| format!("writing {out_path}: {e}"))?;

    eprintln!(
        "signed '{name}' v{version}: {} bytes wasm -> {} bytes artifact -> {out_path}",
        wasm.len(),
        artifact.len()
    );
    Ok(())
}
