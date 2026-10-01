//! Process start lineage. Exit keeps the node so a later parent walk still resolves.
//!
//! Threats: pid reuse would stitch a new process onto an old parent. The walk
//! stops when the parent's generation changed, the parent is missing, a cycle
//! appears, or the depth cap is hit. The map evicts the oldest generation only
//! when a new pid would exceed the cap.

use std::collections::{HashMap, HashSet};

const DEFAULT_CAP: usize = 4096;
const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone)]
struct Node {
    generation: u64,
    ppid: u32,
    parent_generation: u64,
    exe: String,
}

#[derive(Debug)]
pub struct Lineage {
    cap: usize,
    next: u64,
    nodes: HashMap<u32, Node>,
}

impl Lineage {
    #[must_use]
    pub fn new() -> Self {
        Self::with_cap(DEFAULT_CAP)
    }

    #[must_use]
    pub fn with_cap(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            next: 1,
            nodes: HashMap::new(),
        }
    }

    pub fn observe_start(&mut self, pid: u32, ppid: u32, exe: &str) {
        if pid == 0 {
            return;
        }
        if !self.nodes.contains_key(&pid)
            && self.nodes.len() >= self.cap
            && let Some(old) = self.oldest_pid()
        {
            self.nodes.remove(&old);
        }
        let parent_generation = if ppid == 0 {
            0
        } else {
            self.nodes.get(&ppid).map(|n| n.generation).unwrap_or(0)
        };
        let generation = self.next;
        self.next = self.next.saturating_add(1);
        self.nodes.insert(
            pid,
            Node {
                generation,
                ppid,
                parent_generation,
                exe: exe.to_owned(),
            },
        );
    }

    pub fn observe_exit(&mut self, _pid: u32) {}

    #[must_use]
    pub fn contains(&self, pid: u32) -> bool {
        self.nodes.contains_key(&pid)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    #[must_use]
    pub fn ancestors(&self, pid: u32) -> Vec<String> {
        let Some(start) = self.nodes.get(&pid) else {
            return Vec::new();
        };
        let mut ppid = start.ppid;
        let mut parent_generation = start.parent_generation;
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        seen.insert(pid);
        for _ in 0..MAX_DEPTH {
            if ppid == 0 || parent_generation == 0 || !seen.insert(ppid) {
                break;
            }
            let Some(parent) = self.nodes.get(&ppid) else {
                break;
            };
            if parent.generation != parent_generation {
                break;
            }
            out.push(parent.exe.clone());
            ppid = parent.ppid;
            parent_generation = parent.parent_generation;
        }
        out
    }

    fn oldest_pid(&self) -> Option<u32> {
        self.nodes
            .iter()
            .min_by_key(|(_, node)| node.generation)
            .map(|(pid, _)| *pid)
    }
}

impl Default for Lineage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuse_cycle_depth_and_exit_keep_the_contract() {
        let mut lin = Lineage::with_cap(2);
        lin.observe_start(1, 0, "/bin/a");
        lin.observe_start(2, 0, "/bin/b");
        lin.observe_start(3, 0, "/bin/c");
        assert!(!lin.contains(1));
        assert!(lin.contains(2));
        assert!(lin.contains(3));
        lin.observe_start(2, 0, "/bin/b2");
        assert!(lin.contains(3));
        assert_eq!(lin.len(), 2);
        assert!(!lin.is_empty());

        let mut chain = Lineage::new();
        chain.observe_start(1, 0, "/usr/sbin/nocved");
        chain.observe_start(10, 1, "/usr/bin/child");
        assert_eq!(chain.ancestors(10), vec!["/usr/sbin/nocved".to_owned()]);
        chain.observe_start(1, 0, "/usr/sbin/nocved");
        assert!(chain.ancestors(10).is_empty());
        chain.observe_exit(10);
        assert!(chain.contains(10));

        let mut cyc = Lineage::new();
        cyc.observe_start(5, 0, "/bin/a");
        cyc.observe_start(6, 5, "/bin/b");
        cyc.observe_start(5, 6, "/bin/a");
        assert_eq!(cyc.ancestors(5), vec!["/bin/b".to_owned()]);

        let mut deep = Lineage::new();
        deep.observe_start(1, 0, "/bin/p1");
        for pid in 2..=40 {
            deep.observe_start(pid, pid - 1, &format!("/bin/p{pid}"));
        }
        let ancestors = deep.ancestors(40);
        assert_eq!(ancestors.len(), MAX_DEPTH);
        assert_eq!(ancestors[0], "/bin/p39");
    }
}
