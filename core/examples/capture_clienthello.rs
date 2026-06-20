//! `capture-clienthello` — dump the ClientHello our boring profile emits + its JA4 (ADR 0006 §4).
//!
//! Run: `cargo run -p spark-core --example capture_clienthello --features anytls -- [sni]`
//! (defaults SNI to `www.example.com`). Use it to refresh the anchor or eyeball the fingerprint;
//! the `flint_tls::anchor::ANCHOR_JA4` test is the CI drift guard.

#[cfg(feature = "anytls")]
fn main() {
    use flint_tls::anchor::{capture_client_hello, ANCHOR_JA4};
    use flint_tls::ja4::ja4_of_record;
    use flint_tls::Profile;

    let sni = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "www.example.com".to_string());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let ch = rt
        .block_on(capture_client_hello(&Profile::default(), &sni))
        .expect("capture ClientHello");

    let ja4 = ja4_of_record(&ch).expect("compute JA4");
    println!("sni         : {sni}");
    println!("clienthello : {} bytes", ch.len());
    println!(
        "hex         : {}",
        ch.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    println!("ja4         : {ja4}");
    println!("anchor ja4  : {ANCHOR_JA4}");
    println!(
        "drift       : {}",
        if ja4 == ANCHOR_JA4 {
            "none (matches anchor)"
        } else {
            "DRIFTED"
        }
    );
}

#[cfg(not(feature = "anytls"))]
fn main() {
    eprintln!("build with --features anytls: cargo run -p spark-core --example capture_clienthello --features anytls");
    std::process::exit(1);
}
