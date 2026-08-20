//! Run the Unbounded consumer against the parameters a live `config_raw.json` actually delivered,
//! and print its event stream.
//!
//! The tunnel runs this inside a root-owned system extension whose diagnostics are unreadable from a
//! user shell, so a failing consumer surfaces as nothing more than a blank latency cell in server
//! selection. This harness runs the same code in a normal process where `AttemptFailed { error }` is
//! visible.
//!
//! Usage: cargo run --example consumer_probe --features spark-transport -- [path-to-config_raw.json]

use std::sync::Arc;
use std::time::Duration;

use spark_sharing::{
    ephemeral_quic_server_config, start_consumer, ConsumerRuntimeConfig, FreddieSignaler,
};

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/Library/Application Support/org.getlantern.spark/config/config_raw.json")
    });
    let raw = std::fs::read_to_string(&path).expect("read config_raw.json");
    let json: serde_json::Value = serde_json::from_str(&raw).expect("parse config_raw.json");

    // The consumer's parameters ride on the outbound, not the top-level (donor) block.
    let outbound = json["options"]["outbounds"]
        .as_array()
        .expect("outbounds array")
        .iter()
        .find(|o| o["type"] == "unbounded")
        .expect("no unbounded outbound in this config — nothing to probe");

    let base = outbound["discovery_srv"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| json["unbounded"]["discovery_srv"].as_str().unwrap_or(""));
    let path_part = json["unbounded"]["discovery_endpoint"]
        .as_str()
        .unwrap_or("");
    let signaling = match (
        base.trim_end_matches('/'),
        path_part.trim_start_matches('/'),
    ) {
        (b, "") => b.to_string(),
        (b, p) => format!("{b}/{p}"),
    };
    let stun: Vec<String> = outbound["stun_servers"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    println!("signaling : {signaling}");
    println!("stun      : {} servers", stun.len());
    println!("egress    : {}", outbound["egress_addr"]);
    println!();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async move {
        let signaler = match FreddieSignaler::new(&signaling) {
            Ok(s) => s,
            Err(e) => {
                println!("!! building the signaler failed: {e}");
                return;
            }
        };
        let quic = ephemeral_quic_server_config().expect("ephemeral QUIC config");
        let mut cfg = ConsumerRuntimeConfig::new(quic, "consumer-probe-harness".to_string());
        cfg.stun_urls = stun;
        // Slots default to 1 so the log reads as one story; raise it to sample availability faster.
        let slots: usize = std::env::var("SLOTS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        cfg.concurrent_sessions = slots;
        // Tunables under test. The shipped defaults are 500ms / 5s; the hypothesis is that 500ms is
        // too little to gather server-reflexive candidates from 16 STUN servers, so the offer carries
        // host candidates only and a NATed donor can never pair.
        let patience_ms: u64 = std::env::var("PATIENCE_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(500);
        let nat_secs: u64 = std::env::var("NAT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);
        cfg.candidate_patience = Duration::from_millis(patience_ms);
        cfg.nat_timeout = Duration::from_secs(nat_secs);
        println!("candidate_patience={patience_ms}ms  nat_timeout={nat_secs}s\n");

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let handle = match start_consumer(cfg, Arc::new(signaler), Some(tx)) {
            Ok(h) => h,
            Err(e) => {
                println!("!! start_consumer failed: {e}");
                return;
            }
        };

        println!("consumer started; watching events for 45s\n");
        let secs: u64 = std::env::var("RUN_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(45);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                ev = rx.recv() => match ev {
                    Some(e) => println!("EVENT slot={} {:?}", e.slot, e.event),
                    None => break,
                },
            }
        }
        println!("\nstopping");
        let _ = handle.stop().await;
    });
}
