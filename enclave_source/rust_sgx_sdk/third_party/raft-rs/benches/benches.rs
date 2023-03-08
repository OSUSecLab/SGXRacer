#![allow(dead_code)] // Due to criterion we need this to avoid warnings.
#![cfg_attr(feature = "cargo-clippy", allow(let_and_return))] // Benches often artificially return values. Allow it.

extern crate criterion;
extern crate env_logger;
extern crate raft;

use criterion::Criterion;
use std::time::Duration;

mod suites;

pub const DEFAULT_RAFT_SETS: [(usize, usize); 4] = [(0, 0), (3, 1), (5, 2), (7, 3)];

fn main() {
    criterion::init_logging();
    let mut c = Criterion::default()
        // Configure defaults before overriding with args.
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
        .configure_from_args();

    suites::bench_raft(&mut c);
    suites::bench_raw_node(&mut c);
    suites::bench_progress(&mut c);
    suites::bench_progress_set(&mut c);

    c.final_summary();
}
