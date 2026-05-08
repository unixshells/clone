## Summary

<!-- Brief description of what this PR does and why -->

## Changes

<!-- Bullet list of key changes -->

## Test Plan

- [ ] `make ci` passes locally (fmt + clippy + test + deny + audit)
- [ ] `cargo nextest run` passes (or `cargo test` if nextest not installed)
- [ ] E2E tests pass when networking, storage, or boot paths changed
- [ ] Manual verification done (describe below)

## CI dashboard

After CI completes, the **`CI · Build & Test`** sticky comment in this PR
shows: per-job duration, test counts (with delta vs base), top-10
slowest tests, per-binary breakdown, Cargo.lock diff, and any security
advisories. The Mermaid **CI flow** graph showing per-job result is in
the run's job summary tab.

## Conventional commits

This repo uses [Conventional Commits](https://www.conventionalcommits.org/).
Header format: `type(scope): summary`. Common types: `feat`, `fix`,
`refactor`, `test`, `docs`, `chore`, `ci`, `perf`. Example:
`fix(virtio): reject sector overflow in do_read/do_write`.

## Notes

<!-- Any additional context, trade-offs, or follow-up work -->
