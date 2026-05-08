//! Sanity tests that timing primitives we rely on actually return promptly.
//!
//! Regression guard for Bug #1: when the agent was forked from PID 1 of the
//! initrd, blocking sleeps (nanosleep / usleep / std::thread::sleep) never
//! woke. The fix replaced them with sched_yield. These tests don't reproduce
//! the in-guest scheduler problem (you'd need a real KVM context for that),
//! but they catch the dumber regression of someone replacing a sleep call
//! with a stub that doesn't actually sleep AND doesn't return either, or a
//! libc binding that's wired up wrong on a new platform / toolchain.

use std::time::{Duration, Instant};

const DEADLINE_MS: u128 = 200;

#[test]
fn usleep_returns_within_deadline() {
    let start = Instant::now();
    unsafe {
        libc::usleep(50_000);
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < DEADLINE_MS,
        "usleep(50ms) returned in {elapsed:?} — exceeds {DEADLINE_MS}ms deadline"
    );
    assert!(
        elapsed >= Duration::from_millis(40),
        "usleep(50ms) returned in {elapsed:?} — too fast, not actually sleeping?"
    );
}

#[test]
fn nanosleep_returns_within_deadline() {
    let start = Instant::now();
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 50_000_000,
    };
    unsafe {
        libc::nanosleep(&ts, std::ptr::null_mut());
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < DEADLINE_MS,
        "nanosleep(50ms) returned in {elapsed:?} — exceeds {DEADLINE_MS}ms deadline"
    );
}

#[test]
fn sched_yield_returns_immediately() {
    // sched_yield is the agent's blocking-sleep replacement. Must always
    // return; an infinite loop here would freeze the whole loop.
    let start = Instant::now();
    for _ in 0..1000 {
        unsafe {
            libc::sched_yield();
        }
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "1000× sched_yield took {elapsed:?} — kernel scheduler stuck?"
    );
}
