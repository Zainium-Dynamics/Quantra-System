/// Runtime metrics and monitoring for Quantra init system
///
/// Exports metrics in Prometheus format at /run/quantra/metrics
/// Includes boot time, service status, resource usage, etc.
use anyhow::Result;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct MetricsCollector {
    boot_start: Instant,
    services_started: AtomicU64,
    services_failed: AtomicU64,
    total_memory_kb: AtomicU64,
    control_commands: AtomicU64,
}

impl MetricsCollector {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            boot_start: Instant::now(),
            services_started: AtomicU64::new(0),
            services_failed: AtomicU64::new(0),
            total_memory_kb: AtomicU64::new(0),
            control_commands: AtomicU64::new(0),
        })
    }

    pub fn record_service_started(&self) {
        self.services_started.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_service_failed(&self) {
        self.services_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_control_command(&self) {
        self.control_commands.fetch_add(1, Ordering::Relaxed);
    }

    pub fn update_memory_usage(&self, kb: u64) {
        self.total_memory_kb.store(kb, Ordering::Relaxed);
    }

    pub fn export_metrics(&self, path: &Path) -> Result<()> {
        let uptime = self.boot_start.elapsed().as_secs();
        let services_started = self.services_started.load(Ordering::Relaxed);
        let services_failed = self.services_failed.load(Ordering::Relaxed);
        let control_commands = self.control_commands.load(Ordering::Relaxed);
        let memory_kb = self.total_memory_kb.load(Ordering::Relaxed);

        let metrics = format!(
            "# Quantra Init System Metrics\n\
             # HELP quantra_uptime_seconds Time since boot started\n\
             # TYPE quantra_uptime_seconds gauge\n\
             quantra_uptime_seconds {}\n\
             \n\
             # HELP quantra_services_started_total Total services successfully started\n\
             # TYPE quantra_services_started_total counter\n\
             quantra_services_started_total {}\n\
             \n\
             # HELP quantra_services_failed_total Total services that failed to start\n\
             # TYPE quantra_services_failed_total counter\n\
             quantra_services_failed_total {}\n\
             \n\
             # HELP quantra_control_commands_total Total control socket commands processed\n\
             # TYPE quantra_control_commands_total counter\n\
             quantra_control_commands_total {}\n\
             \n\
             # HELP quantra_memory_usage_kb Current memory usage in KB\n\
             # TYPE quantra_memory_usage_kb gauge\n\
             quantra_memory_usage_kb {}\n\
             \n",
            uptime, services_started, services_failed, control_commands, memory_kb
        );

        fs::write(path, metrics)?;
        Ok(())
    }

    /// Start a background thread that periodically updates metrics
    pub fn start_background_updater(self: Arc<Self>) {
        std::thread::spawn(move || {
            loop {
                // Read actual RSS from /proc/self/statm (field index 1 = RSS in pages)
                let memory_kb = read_rss_kb();
                self.update_memory_usage(memory_kb);

                // Export metrics
                let metrics_path = Path::new("/run/quantra/metrics");
                if let Err(e) = self.export_metrics(metrics_path) {
                    log::warn!("Failed to export metrics: {}", e);
                }

                std::thread::sleep(Duration::from_secs(30)); // Update every 30 seconds
            }
        });
    }
}

/// Read init process RSS in KB from `/proc/self/statm`.
///
/// `/proc/self/statm` format: `<size> <rss> <shared> ...` (all in pages).
/// We take field index 1 (rss) and multiply by `sysconf(_SC_PAGESIZE)` / 1024.
#[inline]
fn read_rss_kb() -> u64 {
    let Ok(content) = std::fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    let rss_pages: u64 = content
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    rss_pages.saturating_mul(page_size) / 1024
}
