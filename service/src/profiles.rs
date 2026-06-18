//! Connection profiles (ADR 0004, slice 3).
//!
//! A profile is a named `core::config::Config`, stored in the privileged service. Secrets (the
//! AnyTLS `password`, the wasm `init_config`) are **write-only over IPC**: blanked on read, and a
//! blanked field on write keeps the stored value — so a read→edit→write round-trip never requires
//! the client to have seen the secret. The store persists to a single root-owned TOML file (one
//! file, profile names as map keys — so a name can't traverse the filesystem), loaded at startup
//! and rewritten on every mutation.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use spark_core::config::Config;
use spark_ipc::{ProfileDoc, ProfileSummary, Validation};
use tracing::warn;

use crate::service::{netstack_of, selected_transport};

/// The on-disk form of the store (a single TOML document). Secrets are stored here in the clear —
/// the file is root-owned, the same trust level as the launch config.
#[derive(Default, Serialize, Deserialize)]
struct StoredProfiles {
    #[serde(default)]
    active: Option<String>,
    #[serde(default)]
    profiles: BTreeMap<String, Config>,
}

/// The privileged set of named connection profiles + which one is active. Persisted to `path`
/// (`None` = in-memory only, e.g. tests).
#[derive(Default)]
pub struct ProfileStore {
    path: Option<PathBuf>,
    profiles: BTreeMap<String, Config>,
    active: Option<String>,
}

impl ProfileStore {
    /// Load the store from `path` (if set + present); a missing file is an empty store, an
    /// unparseable one is logged and ignored (don't wedge the daemon on a corrupt file).
    pub fn load(path: Option<PathBuf>) -> Self {
        let mut store = Self {
            path,
            ..Self::default()
        };
        if let Some(p) = &store.path {
            match std::fs::read_to_string(p) {
                Ok(s) => match toml::from_str::<StoredProfiles>(&s) {
                    Ok(sp) => {
                        store.profiles = sp.profiles;
                        store.active = sp.active;
                    }
                    Err(e) => warn!(error = %e, "ignoring unparseable profiles file"),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // no profiles yet
                Err(e) => warn!(error = %e, "could not read profiles file"),
            }
        }
        store
    }

    /// Persist the store (best-effort; no-op when in-memory). Logged on failure.
    fn save(&self) {
        let Some(p) = &self.path else {
            return;
        };
        let doc = StoredProfiles {
            active: self.active.clone(),
            profiles: self.profiles.clone(),
        };
        match toml::to_string(&doc) {
            Ok(s) => {
                if let Some(dir) = p.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                if let Err(e) = std::fs::write(p, s) {
                    warn!(error = %e, "could not write profiles file");
                }
            }
            Err(e) => warn!(error = %e, "could not serialize profiles"),
        }
    }
    /// Redacted summaries of every stored profile.
    pub fn list(&self) -> Vec<ProfileSummary> {
        self.profiles
            .iter()
            .map(|(name, cfg)| ProfileSummary {
                name: name.clone(),
                transport: selected_transport(cfg),
                stack: netstack_of(cfg),
                has_password: has_password(cfg),
                active: self.active.as_deref() == Some(name),
            })
            .collect()
    }

    /// A profile as a redacted TOML document (secrets blanked), or `None` if absent.
    pub fn get_redacted(&self, name: &str) -> Option<ProfileDoc> {
        let cfg = self.profiles.get(name)?;
        Some(ProfileDoc {
            name: name.to_owned(),
            toml: redacted_toml(cfg),
        })
    }

    /// Create or replace `name` from a TOML config doc. A blanked secret keeps the stored value
    /// (write-only secrets). Returns a parse error (on the client's own input — no stored secret
    /// leaks) when the document is invalid.
    pub fn set(&mut self, name: &str, toml: &str) -> Result<(), String> {
        let mut cfg = Config::from_toml_str(toml).map_err(|e| e.to_string())?;
        if let Some(existing) = self.profiles.get(name) {
            keep_blanked_secrets(&mut cfg, existing);
        }
        self.profiles.insert(name.to_owned(), cfg);
        self.save();
        Ok(())
    }

    /// Remove a profile (and clear it as active if it was).
    pub fn delete(&mut self, name: &str) {
        self.profiles.remove(name);
        if self.active.as_deref() == Some(name) {
            self.active = None;
        }
        self.save();
    }

    /// Select the active profile; errors if there's no such profile.
    pub fn set_active(&mut self, name: &str) -> Result<(), String> {
        if self.profiles.contains_key(name) {
            self.active = Some(name.to_owned());
            self.save();
            Ok(())
        } else {
            Err(format!("no such profile: {name}"))
        }
    }

    /// The active profile's config, if one is selected (for connect-by-active — slice 3b).
    pub fn active(&self) -> Option<&Config> {
        self.active.as_deref().and_then(|n| self.profiles.get(n))
    }
}

/// Validate a TOML config document without storing it.
pub fn validate(toml: &str) -> Validation {
    match Config::from_toml_str(toml) {
        Ok(_) => Validation {
            valid: true,
            error: None,
        },
        Err(e) => Validation {
            valid: false,
            error: Some(e.to_string()),
        },
    }
}

fn has_password(cfg: &Config) -> bool {
    cfg.transport
        .anytls
        .as_ref()
        .is_some_and(|a| !a.password.is_empty())
}

/// Serialize `cfg` to TOML with secret fields blanked.
fn redacted_toml(cfg: &Config) -> String {
    let mut c = cfg.clone();
    if let Some(a) = c.transport.anytls.as_mut() {
        a.password.clear();
    }
    if let Some(w) = c.transport.wasm.as_mut() {
        w.init_config = None;
    }
    c.to_toml_string().unwrap_or_default()
}

/// Where `incoming` blanked a secret, copy the stored one back from `existing`.
fn keep_blanked_secrets(incoming: &mut Config, existing: &Config) {
    if let (Some(inc), Some(old)) = (
        incoming.transport.anytls.as_mut(),
        existing.transport.anytls.as_ref(),
    ) {
        if inc.password.is_empty() && !old.password.is_empty() {
            inc.password = old.password.clone();
        }
    }
    if let (Some(inc), Some(old)) = (
        incoming.transport.wasm.as_mut(),
        existing.transport.wasm.as_ref(),
    ) {
        if inc.init_config.is_none() && old.init_config.is_some() {
            inc.init_config = old.init_config.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANYTLS_TOML: &str = "
[transport.anytls]
server = \"1.2.3.4:443\"
password = \"hunter2\"
";

    #[test]
    fn set_get_redacts_the_password() {
        let mut store = ProfileStore::default();
        store.set("home", ANYTLS_TOML).unwrap();
        let doc = store.get_redacted("home").unwrap();
        assert!(
            !doc.toml.contains("hunter2"),
            "the password must not be echoed back"
        );
        // The stored value is intact even though the read redacted it.
        assert!(has_password(store.profiles.get("home").unwrap()));
    }

    #[test]
    fn write_only_secret_survives_a_read_edit_write_round_trip() {
        let mut store = ProfileStore::default();
        store.set("home", ANYTLS_TOML).unwrap();
        // The client reads (redacted), edits something unrelated, and writes the redacted doc back.
        let edited = store.get_redacted("home").unwrap().toml;
        assert!(!edited.contains("hunter2"));
        store.set("home", &edited).unwrap();
        // The blanked password was preserved, not clobbered.
        assert_eq!(
            store
                .profiles
                .get("home")
                .unwrap()
                .transport
                .anytls
                .as_ref()
                .unwrap()
                .password,
            "hunter2",
            "a blanked secret on write must keep the stored value"
        );
    }

    #[test]
    fn list_active_delete() {
        let mut store = ProfileStore::default();
        store.set("a", ANYTLS_TOML).unwrap();
        store.set("b", "").unwrap(); // empty = all-defaults (direct)
        assert_eq!(store.list().len(), 2);
        assert!(store.set_active("a").is_ok());
        assert!(store.set_active("missing").is_err());
        assert!(store.list().iter().any(|p| p.name == "a" && p.active));
        assert!(store.active().is_some());

        store.delete("a");
        assert_eq!(store.list().len(), 1);
        assert!(
            store.active().is_none(),
            "deleting the active profile clears it"
        );
    }

    #[test]
    fn validate_reports_parse_errors() {
        assert!(validate(ANYTLS_TOML).valid);
        assert!(!validate("[transport]\nbogus_key = 1").valid);
    }

    #[test]
    fn persists_across_reload_including_secrets_and_active() {
        let path = std::env::temp_dir().join(format!("spk-profiles-{}.toml", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let mut store = ProfileStore::load(Some(path.clone()));
            store.set("home", ANYTLS_TOML).unwrap();
            store.set_active("home").unwrap();
        }
        // A fresh load sees the persisted profile, the active selection, and the stored secret.
        let store = ProfileStore::load(Some(path.clone()));
        assert!(store.list().iter().any(|p| p.name == "home" && p.active));
        assert_eq!(
            store
                .active()
                .unwrap()
                .transport
                .anytls
                .as_ref()
                .unwrap()
                .password,
            "hunter2",
            "the stored secret must survive a reload"
        );
        let _ = std::fs::remove_file(&path);
    }
}
