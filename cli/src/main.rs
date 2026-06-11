//! `spark` CLI driver. At M0 this is the workspace's binary target only; the real
//! TUN driver (parse packets, reply to ICMP echo) lands in M1 per `docs/PLAN.md`.

fn main() {
    println!(
        "spark {} — M0 skeleton; TUN driver lands in M1",
        env!("CARGO_PKG_VERSION")
    );
}
