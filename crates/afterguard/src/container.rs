//! Container id join. Privileged comes only from an explicit fact.
//!
//! Threats: a cgroup path that merely contains the word privileged must not
//! flip the privileged predicate. The id is the first 12 hex characters of a
//! 64-hex run. Unknown privileged matches neither true nor false.

use std::collections::HashMap;

use cveguard_proto::GuardEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerFact {
    pub id: String,
    pub privileged: Option<bool>,
    pub runtime: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupHint {
    pub id: String,
    pub runtime: String,
}

#[derive(Debug, Default)]
pub struct ContainerIndex {
    facts: HashMap<String, ContainerFact>,
}

impl ContainerIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, fact: ContainerFact) {
        let Some(key) = key_of(&fact.id) else {
            return;
        };
        self.facts.insert(
            key.clone(),
            ContainerFact {
                id: key,
                privileged: fact.privileged,
                runtime: fact.runtime,
            },
        );
    }

    pub fn observe_cgroup(&mut self, text: &str) {
        let Some(hint) = hint_from_cgroup(text) else {
            return;
        };
        self.facts.entry(hint.id.clone()).or_insert(ContainerFact {
            id: hint.id,
            privileged: None,
            runtime: hint.runtime,
        });
    }

    pub fn apply(&self, ev: &mut GuardEvent) {
        let Some(raw) = ev.container_id.clone() else {
            return;
        };
        let Some(key) = key_of(&raw) else {
            return;
        };
        ev.container_id = Some(key.clone());
        let Some(fact) = self.facts.get(&key) else {
            return;
        };
        if let Some(flag) = fact.privileged {
            ev.privileged = Some(flag);
        }
        if ev.runtime.is_none() {
            ev.runtime = Some(fact.runtime.clone());
        }
    }
}

#[must_use]
pub fn hint_from_cgroup(text: &str) -> Option<CgroupHint> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_hexdigit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            if i - start == 64 {
                let runtime = runtime_before(text, start);
                let id = text[start..start + 12].to_ascii_lowercase();
                return Some(CgroupHint { id, runtime });
            }
        } else {
            i += 1;
        }
    }
    None
}

fn runtime_before(text: &str, start: usize) -> String {
    let mut before = start.saturating_sub(32);
    while before < start && !text.is_char_boundary(before) {
        before += 1;
    }
    let window = &text[before..start];
    if window.contains("crio") {
        "crio".to_owned()
    } else if window.contains("containerd") {
        "containerd".to_owned()
    } else if window.contains("docker") {
        "docker".to_owned()
    } else {
        "unknown".to_owned()
    }
}

fn key_of(id: &str) -> Option<String> {
    if id.len() < 12 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(id[..12].to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cveguard_proto::model::Kind;
    use cveguard_proto::{Origin, SCHEMA_VERSION};

    fn event(id: &str) -> GuardEvent {
        GuardEvent {
            schema_version: SCHEMA_VERSION,
            kind: Kind::Container,
            origin: Origin::Ring,
            observed_at_ms: 1,
            pid: None,
            ppid: None,
            uid: None,
            exe: None,
            comm: None,
            args: Vec::new(),
            remote: None,
            package: None,
            version: None,
            container_id: Some(id.to_owned()),
            privileged: None,
            runtime: None,
            severity: None,
            ancestors: Vec::new(),
        }
    }

    #[test]
    fn cgroup_join_does_not_infer_privileged() {
        let id64 = "ab".repeat(32);
        let text = format!("/run/privileged/docker-{id64}");
        let hint = hint_from_cgroup(&text).expect("hint");
        assert_eq!(hint.id, "abababababab");
        assert_eq!(hint.runtime, "docker");

        let mut unknown = ContainerIndex::new();
        unknown.observe_cgroup(&text);
        let mut ev = event(&id64);
        unknown.apply(&mut ev);
        assert_eq!(ev.container_id.as_deref(), Some("abababababab"));
        assert_eq!(ev.privileged, None);
        assert_eq!(ev.runtime.as_deref(), Some("docker"));
        let encoded = serde_json::to_string(&ev).expect("json");
        assert!(!encoded.contains("\"privileged\":true"));

        let mut joined = ContainerIndex::new();
        joined.insert(ContainerFact {
            id: id64,
            privileged: Some(true),
            runtime: "docker".to_owned(),
        });
        let mut ev = event(&hint.id);
        joined.apply(&mut ev);
        assert_eq!(ev.privileged, Some(true));
        assert_eq!(ev.container_id.as_deref(), Some(hint.id.as_str()));

        let bare = "z".repeat(40) + &"cd".repeat(32);
        assert_eq!(hint_from_cgroup(&bare).expect("hint").runtime, "unknown");
    }
}
