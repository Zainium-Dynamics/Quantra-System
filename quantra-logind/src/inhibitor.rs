/// Inhibitor Manager — block/delay power actions with automatic cleanup
///
/// # Inhibitor types
///
/// `Block` inhibitors prevent an action until explicitly released.
/// `Delay` inhibitors ask logind to wait up to `InhibitDelayMaxSec` seconds
/// before proceeding (e.g. to allow an app to save state).
///
/// # Flatpak / portal compatibility
///
/// xdg-session-portal and GNOME apps take inhibitors via D-Bus/logind.
/// quantra-logind exposes the same semantics via JSON socket so portals
/// can be adapted to call us.
///
/// # COSMIC desktop
///
/// COSMIC shell takes `HandlePowerKey` and `HandleLidSwitch` inhibitors
/// when the power manager UI is open to prevent accidental shutdown.
use crate::types::*;
use std::collections::HashMap;
use std::time::Instant;

pub struct InhibitorManager {
    inhibitors: HashMap<InhibitorId, Inhibitor>,
    next_id: InhibitorId,
}

impl InhibitorManager {
    pub fn new() -> Self {
        Self {
            inhibitors: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn take(
        &mut self,
        what: Vec<InhibitWhat>,
        who: String,
        why: String,
        mode: InhibitMode,
        uid: u32,
        pid: u32,
    ) -> InhibitorId {
        let id = self.next_id;
        self.next_id += 1;
        log::info!(
            "Inhibitor {} [{:?}]: {} ({}) mode={:?} uid={} pid={}",
            id,
            what,
            who,
            why,
            mode,
            uid,
            pid
        );
        self.inhibitors.insert(
            id,
            Inhibitor {
                id,
                what,
                who,
                why,
                mode,
                uid,
                pid,
                created: now_unix(),
            },
        );
        id
    }

    pub fn release(&mut self, id: InhibitorId) -> bool {
        self.inhibitors
            .remove(&id)
            .map(|i| log::info!("Inhibitor {} released ({})", id, i.who))
            .is_some()
    }

    /// Release all inhibitors held by a dead process (auto-cleanup on PID exit).
    #[allow(dead_code)]
    pub fn release_by_pid(&mut self, pid: u32) {
        let dead: Vec<InhibitorId> = self
            .inhibitors
            .values()
            .filter(|i| i.pid == pid)
            .map(|i| i.id)
            .collect();
        for id in dead {
            self.release(id);
        }
    }

    /// Check if any Block inhibitor prevents `what`.
    pub fn is_blocked(&self, what: &InhibitWhat) -> bool {
        self.inhibitors
            .values()
            .any(|i| i.mode == InhibitMode::Block && i.what.contains(what))
    }

    /// Check if any Delay inhibitor is held for `what`.
    pub fn has_delay(&self, what: &InhibitWhat) -> bool {
        self.inhibitors
            .values()
            .any(|i| i.mode == InhibitMode::Delay && i.what.contains(what))
    }

    /// Check if any Block inhibitor prevents the given handle action.
    pub fn is_handle_blocked(&self, what: &InhibitWhat) -> bool {
        self.inhibitors
            .values()
            .any(|i| i.mode == InhibitMode::Block && i.what.contains(what))
    }

    /// Wait up to `max_sec` seconds for all Delay inhibitors on `what` to be released.
    /// Returns true if cleared, false if timed out.
    #[allow(dead_code)]
    pub fn wait_delay_cleared(&self, what: &InhibitWhat, max_sec: u64) -> bool {
        let start = Instant::now();
        let limit = std::time::Duration::from_secs(max_sec);
        while start.elapsed() < limit {
            if !self.has_delay(what) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        log::warn!(
            "Delay inhibitors on {:?} did not clear within {}s",
            what,
            max_sec
        );
        false
    }

    /// List all held inhibitors.
    pub fn all(&self) -> Vec<&Inhibitor> {
        let mut v: Vec<&Inhibitor> = self.inhibitors.values().collect();
        v.sort_by_key(|i| i.id);
        v
    }

    /// Purge inhibitors for PIDs that no longer exist.
    pub fn gc_dead_pids(&mut self) {
        let dead: Vec<InhibitorId> = self
            .inhibitors
            .values()
            .filter(|i| !pid_exists(i.pid))
            .map(|i| i.id)
            .collect();
        for id in dead {
            if let Some(i) = self.inhibitors.remove(&id) {
                log::info!("GC: inhibitor {} from dead pid={} ({})", id, i.pid, i.who);
            }
        }
    }
}

fn pid_exists(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
}
