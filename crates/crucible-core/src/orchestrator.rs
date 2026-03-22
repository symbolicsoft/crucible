use crate::harness::{Harness, HarnessError};
use crate::verdict::{Report, TestMeta, TestOutcome, TestResult};
use std::time::Instant;

/// A single test case that can be run against a harness.
pub trait TestCase: Send + Sync {
    /// Metadata describing this test.
    fn meta(&self, parameter_set: &str) -> TestMeta;

    /// Execute the test against the given harness. Returns the outcome.
    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome;
}

/// A named collection of test cases (e.g., "compression", "ntt").
pub struct TestCategory {
    pub name: String,
    pub tests: Vec<Box<dyn TestCase>>,
}

/// A complete test battery (e.g., "ml-kem").
pub struct Battery {
    pub name: String,
    pub categories: Vec<TestCategory>,
    pub parameter_sets: Vec<String>,
}

/// Configuration for a test run.
pub struct RunConfig {
    /// Only run tests from these categories (empty = all).
    pub categories: Vec<String>,
    /// Only run these parameter sets (empty = all from battery).
    pub parameter_sets: Vec<String>,
    /// Only run tests whose ID contains this substring.
    pub filter: Option<String>,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            categories: Vec::new(),
            parameter_sets: Vec::new(),
            filter: None,
        }
    }
}

/// Run a battery against a harness, producing a report.
pub fn run_battery(
    battery: &Battery,
    harness: &mut Harness,
    config: &RunConfig,
) -> Report {
    let mut report = Report::new(&battery.name, &harness.implementation);

    let param_sets = if config.parameter_sets.is_empty() {
        &battery.parameter_sets
    } else {
        &config.parameter_sets
    };

    for category in &battery.categories {
        // Filter categories.
        if !config.categories.is_empty()
            && !config.categories.iter().any(|c| c == &category.name)
        {
            continue;
        }

        for test in &category.tests {
            for param_set in param_sets {
                let meta = test.meta(param_set);

                // Filter by test ID substring.
                if let Some(ref filter) = config.filter {
                    if !meta.id.contains(filter.as_str()) {
                        continue;
                    }
                }

                let start = Instant::now();
                let outcome = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    test.run(harness, param_set)
                })) {
                    Ok(outcome) => outcome,
                    Err(_) => TestOutcome::Error {
                        message: "test panicked".to_string(),
                    },
                };
                let duration_us = start.elapsed().as_micros() as u64;

                report.add_result(TestResult {
                    meta,
                    outcome,
                    duration_us,
                    parameter_set: param_set.clone(),
                });
            }
        }
    }

    report
}

/// Helper: create a failing TestOutcome from a HarnessError.
pub fn harness_error_to_outcome(err: &HarnessError) -> TestOutcome {
    match err {
        HarnessError::Unsupported(func) => TestOutcome::Skip {
            reason: format!("harness does not support function: {func}"),
        },
        other => TestOutcome::Error {
            message: other.to_string(),
        },
    }
}
