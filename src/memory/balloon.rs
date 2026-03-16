use std::time::{Duration, Instant};

/// Balloon policy state machine.
///
/// Implements asymmetric timing with hysteresis:
/// - Deflate: immediate on activity
/// - Inflate: graduated after sustained idle
/// - Cooldown: 60s after deflate, 3min if bursty
pub struct BalloonPolicy {
    /// Current balloon size in pages (inflated = memory reclaimed from guest)
    balloon_pages: u64,

    /// Maximum reclaimable pages (total guest pages minus floor)
    max_reclaimable: u64,

    /// Minimum pages guest must retain (floor)
    floor_pages: u64,

    /// Last time guest was active
    last_active: Instant,

    /// Last time balloon was deflated
    last_deflate: Instant,

    /// Activity transitions in recent window (for burstiness tracking)
    transitions: Vec<Instant>,

    /// Current guest state
    state: GuestState,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GuestState {
    Active,
    Idle,
}

#[derive(Debug)]
pub enum BalloonAction {
    /// Inflate balloon by N pages (reclaim from guest)
    Inflate(u64),
    /// Deflate balloon by N pages (give back to guest)
    Deflate(u64),
    /// No change
    Hold,
}

impl BalloonPolicy {
    pub fn new(total_pages: u64, floor_mb: u32) -> Self {
        let floor_pages = (floor_mb as u64 * 1024 * 1024) / 4096;
        let max_reclaimable = total_pages.saturating_sub(floor_pages);

        Self {
            balloon_pages: 0,
            max_reclaimable,
            floor_pages,
            last_active: Instant::now(),
            last_deflate: Instant::now(),
            transitions: Vec::new(),
            state: GuestState::Active,
        }
    }

    /// Report guest activity. Returns action to take.
    pub fn report_activity(&mut self, active: bool) -> BalloonAction {
        let now = Instant::now();
        let new_state = if active { GuestState::Active } else { GuestState::Idle };

        // Track state transitions for burstiness
        if new_state != self.state {
            self.transitions.push(now);
            // Keep only transitions from last 5 minutes
            let cutoff = now - Duration::from_secs(300);
            self.transitions.retain(|t| *t > cutoff);
        }

        self.state = new_state;

        match self.state {
            GuestState::Active => {
                self.last_active = now;

                if self.balloon_pages > 0 {
                    // Immediate full deflate — responsiveness is sacred
                    let deflate = self.balloon_pages;
                    self.balloon_pages = 0;
                    self.last_deflate = now;
                    return BalloonAction::Deflate(deflate);
                }

                BalloonAction::Hold
            }
            GuestState::Idle => {
                let idle_duration = now.duration_since(self.last_active);
                let cooldown = self.cooldown_duration();

                // Respect cooldown after deflate
                if now.duration_since(self.last_deflate) < cooldown {
                    return BalloonAction::Hold;
                }

                // Graduated inflation based on idle duration
                let target_fraction = if idle_duration > Duration::from_secs(300) {
                    1.0 // 5min+ idle: reclaim to floor
                } else if idle_duration > Duration::from_secs(120) {
                    0.5 // 2min idle: reclaim 50%
                } else if idle_duration > Duration::from_secs(30) {
                    0.25 // 30s idle: reclaim 25%
                } else {
                    return BalloonAction::Hold; // Not idle long enough
                };

                let target_pages = (self.max_reclaimable as f64 * target_fraction) as u64;

                if target_pages > self.balloon_pages {
                    let inflate = target_pages - self.balloon_pages;
                    self.balloon_pages = target_pages;
                    BalloonAction::Inflate(inflate)
                } else {
                    BalloonAction::Hold
                }
            }
        }
    }

    /// Cooldown duration depends on burstiness.
    /// 3+ transitions in 5min = bursty → 3min cooldown.
    /// Otherwise → 60s cooldown.
    fn cooldown_duration(&self) -> Duration {
        if self.transitions.len() >= 3 {
            Duration::from_secs(180)
        } else {
            Duration::from_secs(60)
        }
    }

    pub fn balloon_pages(&self) -> u64 {
        self.balloon_pages
    }

    pub fn state(&self) -> GuestState {
        self.state
    }

    /// For testing: create a policy with controllable timestamps.
    #[cfg(test)]
    fn new_with_times(
        total_pages: u64,
        floor_mb: u32,
        last_active: Instant,
        last_deflate: Instant,
    ) -> Self {
        let floor_pages = (floor_mb as u64 * 1024 * 1024) / 4096;
        let max_reclaimable = total_pages.saturating_sub(floor_pages);

        Self {
            balloon_pages: 0,
            max_reclaimable,
            floor_pages,
            last_active,
            last_deflate,
            transitions: Vec::new(),
            state: GuestState::Active,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 256 MB total, 64 MB floor => max_reclaimable = (256-64) MB in pages = 49152 pages
    const TOTAL_PAGES: u64 = 256 * 1024 * 1024 / 4096; // 65536
    const FLOOR_MB: u32 = 64;
    // max_reclaimable = (256 - 64) * 256 = 49152 pages

    #[test]
    fn test_new_policy_initial_state() {
        let policy = BalloonPolicy::new(TOTAL_PAGES, FLOOR_MB);
        assert_eq!(policy.balloon_pages(), 0);
        assert_eq!(policy.state(), GuestState::Active);
    }

    #[test]
    fn test_active_report_no_balloon_is_hold() {
        let mut policy = BalloonPolicy::new(TOTAL_PAGES, FLOOR_MB);
        match policy.report_activity(true) {
            BalloonAction::Hold => {}
            other => panic!("Expected Hold, got {:?}", other),
        }
    }

    #[test]
    fn test_idle_less_than_30s_is_hold() {
        // Just created, so last_active is now. Reporting idle immediately
        // should hold because idle_duration < 30s.
        let mut policy = BalloonPolicy::new(TOTAL_PAGES, FLOOR_MB);
        match policy.report_activity(false) {
            BalloonAction::Hold => {}
            other => panic!("Expected Hold, got {:?}", other),
        }
    }

    #[test]
    fn test_graduated_inflation_25_percent_after_30s() {
        let now = Instant::now();
        let last_active = now - Duration::from_secs(35);
        let last_deflate = now - Duration::from_secs(120); // well past cooldown
        let mut policy = BalloonPolicy::new_with_times(TOTAL_PAGES, FLOOR_MB, last_active, last_deflate);
        policy.state = GuestState::Idle;

        match policy.report_activity(false) {
            BalloonAction::Inflate(pages) => {
                // 25% of max_reclaimable = 49152 * 0.25 = 12288
                assert_eq!(pages, 12288);
                assert_eq!(policy.balloon_pages(), 12288);
            }
            other => panic!("Expected Inflate, got {:?}", other),
        }
    }

    #[test]
    fn test_graduated_inflation_50_percent_after_2min() {
        let now = Instant::now();
        let last_active = now - Duration::from_secs(130);
        let last_deflate = now - Duration::from_secs(200);
        let mut policy = BalloonPolicy::new_with_times(TOTAL_PAGES, FLOOR_MB, last_active, last_deflate);
        policy.state = GuestState::Idle;

        match policy.report_activity(false) {
            BalloonAction::Inflate(pages) => {
                // 50% of 49152 = 24576
                assert_eq!(pages, 24576);
                assert_eq!(policy.balloon_pages(), 24576);
            }
            other => panic!("Expected Inflate, got {:?}", other),
        }
    }

    #[test]
    fn test_graduated_inflation_100_percent_after_5min() {
        let now = Instant::now();
        let last_active = now - Duration::from_secs(310);
        let last_deflate = now - Duration::from_secs(400);
        let mut policy = BalloonPolicy::new_with_times(TOTAL_PAGES, FLOOR_MB, last_active, last_deflate);
        policy.state = GuestState::Idle;

        match policy.report_activity(false) {
            BalloonAction::Inflate(pages) => {
                // 100% of 49152
                assert_eq!(pages, 49152);
                assert_eq!(policy.balloon_pages(), 49152);
            }
            other => panic!("Expected Inflate, got {:?}", other),
        }
    }

    #[test]
    fn test_immediate_deflation_on_activity() {
        let now = Instant::now();
        let last_active = now - Duration::from_secs(310);
        let last_deflate = now - Duration::from_secs(400);
        let mut policy = BalloonPolicy::new_with_times(TOTAL_PAGES, FLOOR_MB, last_active, last_deflate);
        policy.state = GuestState::Idle;

        // First inflate fully
        policy.report_activity(false);
        assert_eq!(policy.balloon_pages(), 49152);

        // Now report active — should immediately deflate all
        match policy.report_activity(true) {
            BalloonAction::Deflate(pages) => {
                assert_eq!(pages, 49152);
                assert_eq!(policy.balloon_pages(), 0);
            }
            other => panic!("Expected Deflate, got {:?}", other),
        }
    }

    #[test]
    fn test_cooldown_60s_after_deflate() {
        let now = Instant::now();
        let last_active = now - Duration::from_secs(310);
        let last_deflate = now - Duration::from_secs(400);
        let mut policy = BalloonPolicy::new_with_times(TOTAL_PAGES, FLOOR_MB, last_active, last_deflate);
        policy.state = GuestState::Idle;

        // Inflate
        policy.report_activity(false);
        assert!(policy.balloon_pages() > 0);

        // Deflate
        policy.report_activity(true);
        assert_eq!(policy.balloon_pages(), 0);

        // Now last_deflate is ~now. Try to inflate again while idle.
        // Even though last_active was just set, simulate idle for > 30s
        // by setting last_active back.
        policy.last_active = Instant::now() - Duration::from_secs(35);
        policy.state = GuestState::Idle;

        // Should hold due to cooldown (less than 60s since deflate)
        match policy.report_activity(false) {
            BalloonAction::Hold => {}
            other => panic!("Expected Hold due to cooldown, got {:?}", other),
        }
    }

    #[test]
    fn test_burstiness_extends_cooldown_to_3min() {
        let now = Instant::now();
        let last_active = now - Duration::from_secs(310);
        let last_deflate = now - Duration::from_secs(400);
        let mut policy = BalloonPolicy::new_with_times(TOTAL_PAGES, FLOOR_MB, last_active, last_deflate);
        policy.state = GuestState::Active;

        // Create 3+ transitions in 5 minutes to trigger bursty mode
        // Transition 1: Active -> Idle
        policy.report_activity(false);
        // Transition 2: Idle -> Active
        policy.report_activity(true);
        // Transition 3: Active -> Idle
        policy.report_activity(false);

        assert!(policy.transitions.len() >= 3);

        // Now cooldown should be 3 minutes (180s)
        let cooldown = policy.cooldown_duration();
        assert_eq!(cooldown, Duration::from_secs(180));
    }

    #[test]
    fn test_deflation_during_cooldown_is_still_immediate() {
        let now = Instant::now();
        let last_active = now - Duration::from_secs(310);
        let last_deflate = now - Duration::from_secs(400);
        let mut policy = BalloonPolicy::new_with_times(TOTAL_PAGES, FLOOR_MB, last_active, last_deflate);
        policy.state = GuestState::Idle;

        // Inflate
        policy.report_activity(false);
        let inflated = policy.balloon_pages();
        assert!(inflated > 0);

        // Even if we're in some cooldown state, becoming active should always deflate
        match policy.report_activity(true) {
            BalloonAction::Deflate(pages) => {
                assert_eq!(pages, inflated);
                assert_eq!(policy.balloon_pages(), 0);
            }
            other => panic!("Expected Deflate, got {:?}", other),
        }
    }

    #[test]
    fn test_empty_balloon_deflation_is_hold() {
        let mut policy = BalloonPolicy::new(TOTAL_PAGES, FLOOR_MB);
        assert_eq!(policy.balloon_pages(), 0);

        // Already active with 0 balloon — should Hold
        match policy.report_activity(true) {
            BalloonAction::Hold => {}
            other => panic!("Expected Hold for empty balloon, got {:?}", other),
        }
    }

    #[test]
    fn test_max_reclaimable_calculation() {
        // 128 MB total, 128 MB floor => 0 reclaimable
        let mut policy = BalloonPolicy::new(128 * 256, 128);
        policy.last_active = Instant::now() - Duration::from_secs(310);
        policy.last_deflate = Instant::now() - Duration::from_secs(400);
        policy.state = GuestState::Idle;

        match policy.report_activity(false) {
            BalloonAction::Hold => {}
            other => panic!("Expected Hold when max_reclaimable is 0, got {:?}", other),
        }
    }

    #[test]
    fn test_floor_greater_than_total_pages() {
        // floor > total => max_reclaimable saturates to 0
        let policy = BalloonPolicy::new(100, 1024);
        assert_eq!(policy.max_reclaimable, 0);
    }

    #[test]
    fn test_inflation_is_incremental() {
        let now = Instant::now();
        let last_active = now - Duration::from_secs(35);
        let last_deflate = now - Duration::from_secs(120);
        let mut policy = BalloonPolicy::new_with_times(TOTAL_PAGES, FLOOR_MB, last_active, last_deflate);
        policy.state = GuestState::Idle;

        // Get 25% inflation
        policy.report_activity(false);
        let first = policy.balloon_pages();
        assert_eq!(first, 12288); // 25%

        // Now simulate 2+ minutes idle, report again — should inflate to 50%
        policy.last_active = Instant::now() - Duration::from_secs(130);
        match policy.report_activity(false) {
            BalloonAction::Inflate(pages) => {
                // Going from 25% (12288) to 50% (24576) = inflate by 12288 more
                assert_eq!(pages, 12288);
                assert_eq!(policy.balloon_pages(), 24576);
            }
            other => panic!("Expected incremental Inflate, got {:?}", other),
        }
    }

    #[test]
    fn test_normal_cooldown_is_60s() {
        let policy = BalloonPolicy::new(TOTAL_PAGES, FLOOR_MB);
        assert_eq!(policy.cooldown_duration(), Duration::from_secs(60));
    }
}
