//! Observability: per-VM metrics, host metrics, and structured event logging.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Per-VM metrics
// ---------------------------------------------------------------------------

/// Runtime metrics for a single VM.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VmMetrics {
    /// Private resident set size in bytes.
    pub private_rss_bytes: u64,
    /// Shared (CoW/KSM) resident set size in bytes.
    pub shared_rss_bytes: u64,

    /// Number of CoW faults since boot.
    pub cow_fault_count: u64,
    /// Pages that have diverged from template.
    pub cow_diverged_pages: u64,

    /// Current balloon size in pages.
    pub balloon_current_pages: u64,
    /// Target balloon size in pages.
    pub balloon_target_pages: u64,

    /// Total vCPU execution time in nanoseconds.
    pub vcpu_time_ns: u64,
    /// Number of times vCPUs were parked (HLT).
    pub vcpu_park_count: u64,
    /// Number of times vCPUs were woken.
    pub vcpu_wake_count: u64,

    /// Network bytes received.
    pub net_rx_bytes: u64,
    /// Network bytes transmitted.
    pub net_tx_bytes: u64,
    /// Network packets received.
    pub net_rx_packets: u64,
    /// Network packets transmitted.
    pub net_tx_packets: u64,

    /// Uptime in seconds.
    pub uptime_secs: f64,
}

// ---------------------------------------------------------------------------
// Host-level aggregate metrics
// ---------------------------------------------------------------------------

/// Aggregate metrics across all VMs on this host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostMetrics {
    pub total_vms: u32,
    pub active_vms: u32,
    pub idle_vms: u32,

    /// Ratio of allocated-virtual to physical memory.
    pub overcommit_ratio: f64,
    /// Fraction of pages shared via KSM.
    pub ksm_sharing_ratio: f64,
    /// Cache hit rate for template pool lookups.
    pub template_hit_rate: f64,

    /// Total host memory in bytes.
    pub host_mem_total: u64,
    /// Available host memory in bytes.
    pub host_mem_available: u64,
}

/// Collect host-level metrics by reading /proc and /sys.
///
/// On non-Linux platforms this returns zeroed defaults.
pub fn collect_host_metrics() -> HostMetrics {
    #[cfg(target_os = "linux")]
    {
        collect_host_metrics_linux()
    }
    #[cfg(not(target_os = "linux"))]
    {
        HostMetrics::default()
    }
}

#[cfg(target_os = "linux")]
fn collect_host_metrics_linux() -> HostMetrics {
    let mut hm = HostMetrics::default();

    // Parse /proc/meminfo
    if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
        for line in contents.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                hm.host_mem_total = parse_meminfo_kb(rest) * 1024;
            } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
                hm.host_mem_available = parse_meminfo_kb(rest) * 1024;
            }
        }
    }

    // KSM sharing: pages_sharing / pages_shared gives an idea of ratio
    let pages_sharing = read_sysfs_u64("/sys/kernel/mm/ksm/pages_sharing").unwrap_or(0);
    let pages_shared = read_sysfs_u64("/sys/kernel/mm/ksm/pages_shared").unwrap_or(0);
    if pages_shared > 0 {
        hm.ksm_sharing_ratio = pages_sharing as f64 / pages_shared as f64;
    }

    if hm.host_mem_total > 0 {
        let used = hm.host_mem_total.saturating_sub(hm.host_mem_available);
        hm.overcommit_ratio = used as f64 / hm.host_mem_total as f64;
    }

    hm
}

#[cfg(target_os = "linux")]
fn parse_meminfo_kb(s: &str) -> u64 {
    // Format: "      12345 kB"
    s.trim()
        .split_whitespace()
        .next()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
}

#[cfg(target_os = "linux")]
fn read_sysfs_u64(path: &str) -> Option<u64> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

// ---------------------------------------------------------------------------
// Structured event log
// ---------------------------------------------------------------------------

/// Events emitted by the VMM for observability.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum VmEvent {
    Boot { vm_id: String },
    Shutdown { vm_id: String },
    BalloonInflate { vm_id: String, pages: u64 },
    BalloonDeflate { vm_id: String, pages: u64 },
    OomKill { vm_id: String },
    VcpuPark { vm_id: String, vcpu_id: u32 },
    VcpuWake { vm_id: String, vcpu_id: u32 },
    TemplateHit { vm_id: String, template: String },
    TemplateMiss { vm_id: String, template: String },
}

/// Timestamped event wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampedEvent {
    /// Milliseconds since the EventLogger was created.
    pub timestamp_ms: u64,
    #[serde(flatten)]
    pub event: VmEvent,
}

/// Ring-buffer event logger.
///
/// Stores the most recent `capacity` events in memory.
/// Can be drained to JSON for external consumption.
pub struct EventLogger {
    epoch: Instant,
    buffer: Arc<Mutex<VecDeque<TimestampedEvent>>>,
    capacity: usize,
}

impl EventLogger {
    pub fn new(capacity: usize) -> Self {
        Self {
            epoch: Instant::now(),
            buffer: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity,
        }
    }

    /// Record an event.
    pub fn log(&self, event: VmEvent) {
        let ts = TimestampedEvent {
            timestamp_ms: self.epoch.elapsed().as_millis() as u64,
            event,
        };

        // Also emit via tracing for structured log output.
        tracing::info!(
            event = serde_json::to_string(&ts).unwrap_or_default().as_str(),
            "vm_event"
        );

        let mut buf = self.buffer.lock().unwrap();
        if buf.len() >= self.capacity {
            buf.pop_front();
        }
        buf.push_back(ts);
    }

    /// Return a snapshot of all events currently in the ring buffer.
    pub fn snapshot(&self) -> Vec<TimestampedEvent> {
        self.buffer.lock().unwrap().iter().cloned().collect()
    }

    /// Drain all events from the ring buffer.
    pub fn drain(&self) -> Vec<TimestampedEvent> {
        self.buffer.lock().unwrap().drain(..).collect()
    }

    /// Get a clone-friendly handle (the inner buffer is already Arc).
    pub fn handle(&self) -> EventLoggerHandle {
        EventLoggerHandle {
            epoch: self.epoch,
            buffer: Arc::clone(&self.buffer),
            capacity: self.capacity,
        }
    }
}

/// Cheap, cloneable handle to an EventLogger's buffer.
#[derive(Clone)]
pub struct EventLoggerHandle {
    epoch: Instant,
    buffer: Arc<Mutex<VecDeque<TimestampedEvent>>>,
    capacity: usize,
}

impl EventLoggerHandle {
    pub fn log(&self, event: VmEvent) {
        let ts = TimestampedEvent {
            timestamp_ms: self.epoch.elapsed().as_millis() as u64,
            event,
        };
        let mut buf = self.buffer.lock().unwrap();
        if buf.len() >= self.capacity {
            buf.pop_front();
        }
        buf.push_back(ts);
    }

    pub fn snapshot(&self) -> Vec<TimestampedEvent> {
        self.buffer.lock().unwrap().iter().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// MetricsCollector
// ---------------------------------------------------------------------------

/// Periodically gathers metrics from all subsystems.
///
/// In a full implementation this would poll KVM stats, /proc/<pid>/smaps,
/// virtio counters, etc.  For now it holds per-VM snapshots that subsystems
/// push into.
pub struct MetricsCollector {
    vm_metrics: Arc<Mutex<std::collections::HashMap<String, VmMetrics>>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            vm_metrics: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Update or insert metrics for a VM.
    pub fn update(&self, vm_id: &str, metrics: VmMetrics) {
        self.vm_metrics
            .lock()
            .unwrap()
            .insert(vm_id.to_string(), metrics);
    }

    /// Remove metrics for a destroyed VM.
    pub fn remove(&self, vm_id: &str) {
        self.vm_metrics.lock().unwrap().remove(vm_id);
    }

    /// Get a snapshot of metrics for a specific VM.
    pub fn get(&self, vm_id: &str) -> Option<VmMetrics> {
        self.vm_metrics.lock().unwrap().get(vm_id).cloned()
    }

    /// Get a snapshot of all VM metrics.
    pub fn all(&self) -> std::collections::HashMap<String, VmMetrics> {
        self.vm_metrics.lock().unwrap().clone()
    }

    /// Get a cloneable handle.
    pub fn handle(&self) -> MetricsCollectorHandle {
        MetricsCollectorHandle {
            vm_metrics: Arc::clone(&self.vm_metrics),
        }
    }
}

/// Cheap, cloneable handle to a MetricsCollector.
#[derive(Clone)]
pub struct MetricsCollectorHandle {
    vm_metrics: Arc<Mutex<std::collections::HashMap<String, VmMetrics>>>,
}

impl MetricsCollectorHandle {
    pub fn update(&self, vm_id: &str, metrics: VmMetrics) {
        self.vm_metrics
            .lock()
            .unwrap()
            .insert(vm_id.to_string(), metrics);
    }

    pub fn remove(&self, vm_id: &str) {
        self.vm_metrics.lock().unwrap().remove(vm_id);
    }

    pub fn get(&self, vm_id: &str) -> Option<VmMetrics> {
        self.vm_metrics.lock().unwrap().get(vm_id).cloned()
    }

    pub fn all(&self) -> std::collections::HashMap<String, VmMetrics> {
        self.vm_metrics.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- VmMetrics ---

    #[test]
    fn test_vm_metrics_default_values() {
        let m = VmMetrics::default();
        assert_eq!(m.private_rss_bytes, 0);
        assert_eq!(m.shared_rss_bytes, 0);
        assert_eq!(m.cow_fault_count, 0);
        assert_eq!(m.cow_diverged_pages, 0);
        assert_eq!(m.balloon_current_pages, 0);
        assert_eq!(m.balloon_target_pages, 0);
        assert_eq!(m.vcpu_time_ns, 0);
        assert_eq!(m.vcpu_park_count, 0);
        assert_eq!(m.vcpu_wake_count, 0);
        assert_eq!(m.net_rx_bytes, 0);
        assert_eq!(m.net_tx_bytes, 0);
        assert_eq!(m.net_rx_packets, 0);
        assert_eq!(m.net_tx_packets, 0);
        assert_eq!(m.uptime_secs, 0.0);
    }

    #[test]
    fn test_vm_metrics_serialization() {
        let m = VmMetrics {
            private_rss_bytes: 1024,
            net_rx_bytes: 5000,
            uptime_secs: 42.5,
            ..Default::default()
        };
        let json = serde_json::to_string(&m).unwrap();
        let deserialized: VmMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.private_rss_bytes, 1024);
        assert_eq!(deserialized.net_rx_bytes, 5000);
        assert_eq!(deserialized.uptime_secs, 42.5);
    }

    // --- MetricsCollector ---

    #[test]
    fn test_metrics_collector_update_get() {
        let collector = MetricsCollector::new();
        let m = VmMetrics {
            private_rss_bytes: 4096,
            ..Default::default()
        };
        collector.update("vm-1", m);

        let retrieved = collector.get("vm-1").unwrap();
        assert_eq!(retrieved.private_rss_bytes, 4096);
    }

    #[test]
    fn test_metrics_collector_get_nonexistent() {
        let collector = MetricsCollector::new();
        assert!(collector.get("vm-999").is_none());
    }

    #[test]
    fn test_metrics_collector_remove() {
        let collector = MetricsCollector::new();
        collector.update("vm-1", VmMetrics::default());
        assert!(collector.get("vm-1").is_some());

        collector.remove("vm-1");
        assert!(collector.get("vm-1").is_none());
    }

    #[test]
    fn test_metrics_collector_remove_nonexistent_is_noop() {
        let collector = MetricsCollector::new();
        collector.remove("vm-nonexistent"); // should not panic
    }

    #[test]
    fn test_metrics_collector_all() {
        let collector = MetricsCollector::new();
        collector.update("vm-1", VmMetrics { private_rss_bytes: 1, ..Default::default() });
        collector.update("vm-2", VmMetrics { private_rss_bytes: 2, ..Default::default() });

        let all = collector.all();
        assert_eq!(all.len(), 2);
        assert_eq!(all["vm-1"].private_rss_bytes, 1);
        assert_eq!(all["vm-2"].private_rss_bytes, 2);
    }

    #[test]
    fn test_metrics_collector_update_overwrites() {
        let collector = MetricsCollector::new();
        collector.update("vm-1", VmMetrics { private_rss_bytes: 100, ..Default::default() });
        collector.update("vm-1", VmMetrics { private_rss_bytes: 200, ..Default::default() });

        assert_eq!(collector.get("vm-1").unwrap().private_rss_bytes, 200);
    }

    #[test]
    fn test_metrics_collector_handle() {
        let collector = MetricsCollector::new();
        let handle = collector.handle();

        handle.update("vm-1", VmMetrics { vcpu_time_ns: 999, ..Default::default() });
        assert_eq!(collector.get("vm-1").unwrap().vcpu_time_ns, 999);

        // Handle can also read
        assert_eq!(handle.get("vm-1").unwrap().vcpu_time_ns, 999);

        // Handle can remove
        handle.remove("vm-1");
        assert!(collector.get("vm-1").is_none());
    }

    // --- EventLogger ---

    #[test]
    fn test_event_logger_log_and_snapshot() {
        let logger = EventLogger::new(100);
        logger.log(VmEvent::Boot {
            vm_id: "vm-1".to_string(),
        });
        logger.log(VmEvent::Shutdown {
            vm_id: "vm-1".to_string(),
        });

        let events = logger.snapshot();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn test_event_logger_ring_buffer_overflow() {
        let logger = EventLogger::new(3);

        logger.log(VmEvent::Boot { vm_id: "vm-1".to_string() });
        logger.log(VmEvent::Boot { vm_id: "vm-2".to_string() });
        logger.log(VmEvent::Boot { vm_id: "vm-3".to_string() });
        // Buffer is full now (capacity=3)
        logger.log(VmEvent::Boot { vm_id: "vm-4".to_string() });

        let events = logger.snapshot();
        assert_eq!(events.len(), 3);

        // The oldest event (vm-1) should have been evicted
        match &events[0].event {
            VmEvent::Boot { vm_id } => assert_eq!(vm_id, "vm-2"),
            _ => panic!("Wrong event type"),
        }
        match &events[2].event {
            VmEvent::Boot { vm_id } => assert_eq!(vm_id, "vm-4"),
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_event_logger_drain() {
        let logger = EventLogger::new(100);
        logger.log(VmEvent::Boot { vm_id: "vm-1".to_string() });
        logger.log(VmEvent::Shutdown { vm_id: "vm-1".to_string() });

        let events = logger.drain();
        assert_eq!(events.len(), 2);

        // After drain, buffer is empty
        let events = logger.snapshot();
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn test_event_logger_timestamp_monotonic() {
        let logger = EventLogger::new(100);
        logger.log(VmEvent::Boot { vm_id: "vm-1".to_string() });
        logger.log(VmEvent::Shutdown { vm_id: "vm-1".to_string() });

        let events = logger.snapshot();
        assert!(events[1].timestamp_ms >= events[0].timestamp_ms);
    }

    #[test]
    fn test_event_logger_handle() {
        let logger = EventLogger::new(100);
        let handle = logger.handle();

        handle.log(VmEvent::VcpuPark {
            vm_id: "vm-1".to_string(),
            vcpu_id: 0,
        });

        // Both logger and handle should see the event
        assert_eq!(logger.snapshot().len(), 1);
        assert_eq!(handle.snapshot().len(), 1);
    }

    #[test]
    fn test_event_logger_empty_snapshot() {
        let logger = EventLogger::new(100);
        assert_eq!(logger.snapshot().len(), 0);
    }

    #[test]
    fn test_event_logger_all_event_types() {
        let logger = EventLogger::new(100);
        logger.log(VmEvent::Boot { vm_id: "v".to_string() });
        logger.log(VmEvent::Shutdown { vm_id: "v".to_string() });
        logger.log(VmEvent::BalloonInflate { vm_id: "v".to_string(), pages: 10 });
        logger.log(VmEvent::BalloonDeflate { vm_id: "v".to_string(), pages: 5 });
        logger.log(VmEvent::OomKill { vm_id: "v".to_string() });
        logger.log(VmEvent::VcpuPark { vm_id: "v".to_string(), vcpu_id: 0 });
        logger.log(VmEvent::VcpuWake { vm_id: "v".to_string(), vcpu_id: 0 });
        logger.log(VmEvent::TemplateHit { vm_id: "v".to_string(), template: "t".to_string() });
        logger.log(VmEvent::TemplateMiss { vm_id: "v".to_string(), template: "t".to_string() });

        assert_eq!(logger.snapshot().len(), 9);
    }

    // --- HostMetrics ---

    #[test]
    fn test_host_metrics_default() {
        let hm = HostMetrics::default();
        assert_eq!(hm.total_vms, 0);
        assert_eq!(hm.active_vms, 0);
        assert_eq!(hm.idle_vms, 0);
        assert_eq!(hm.overcommit_ratio, 0.0);
        assert_eq!(hm.ksm_sharing_ratio, 0.0);
        assert_eq!(hm.template_hit_rate, 0.0);
        assert_eq!(hm.host_mem_total, 0);
        assert_eq!(hm.host_mem_available, 0);
    }

    #[test]
    fn test_collect_host_metrics_non_linux_returns_defaults() {
        let hm = collect_host_metrics();
        // On non-Linux, should return defaults; on Linux, should have real values.
        // We just check it doesn't panic and returns a valid struct.
        let _ = hm.total_vms;
        let _ = hm.host_mem_total;
    }

    #[test]
    fn test_host_metrics_serialization() {
        let hm = HostMetrics {
            total_vms: 5,
            host_mem_total: 1024 * 1024 * 1024,
            ..Default::default()
        };
        let json = serde_json::to_string(&hm).unwrap();
        let deserialized: HostMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total_vms, 5);
        assert_eq!(deserialized.host_mem_total, 1024 * 1024 * 1024);
    }

    #[test]
    fn test_vm_event_serialization() {
        let event = VmEvent::BalloonInflate {
            vm_id: "vm-42".to_string(),
            pages: 1000,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("balloon_inflate"));
        assert!(json.contains("vm-42"));
        assert!(json.contains("1000"));
    }

    #[test]
    fn test_timestamped_event_serialization() {
        let ts = TimestampedEvent {
            timestamp_ms: 12345,
            event: VmEvent::Boot { vm_id: "vm-1".to_string() },
        };
        let json = serde_json::to_string(&ts).unwrap();
        assert!(json.contains("12345"));
        assert!(json.contains("boot"));
    }
}
