//! Fetch Spark's server pool from the Lantern `config-new` API (design:
//! `docs/config-new-fetch-design.md`). Direct TLS (no fronting yet), free-tier, disk-cached, fed into
//! [`crate::config::Config::from_config_str`]. Trust is TLS — no signature, matching radiance.

mod cache;
mod http;
mod request;

#[cfg(test)]
mod tests {
    #[test]
    fn module_compiles() {
        // Placeholder smoke test; real behavior is covered in later tasks.
        assert_eq!(2 + 2, 4);
    }
}
