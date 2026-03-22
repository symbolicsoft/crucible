use serde::{Deserialize, Serialize};
use std::fmt;

/// Classification of the bug a test is designed to detect.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BugClass {
    /// Top-level category (e.g., "dead-code", "bounds-check", "timing-leak", "spec-divergence").
    pub category: String,
    /// Specific sub-class (e.g., "rounding", "missing-ntt", "coefficient-range").
    pub subcategory: String,
}

impl BugClass {
    pub fn new(category: &str, subcategory: &str) -> Self {
        Self {
            category: category.to_string(),
            subcategory: subcategory.to_string(),
        }
    }
}

impl fmt::Display for BugClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.category, self.subcategory)
    }
}

/// Reference to a specific location in a NIST standard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecReference {
    /// Which standard (e.g., "FIPS 203", "FIPS 204").
    pub standard: String,
    /// Section, algorithm, and/or line (e.g., "§4.2.1, Eq. 4.7").
    pub location: String,
}

impl SpecReference {
    pub fn fips203(location: &str) -> Self {
        Self {
            standard: "FIPS 203".to_string(),
            location: location.to_string(),
        }
    }

    pub fn fips204(location: &str) -> Self {
        Self {
            standard: "FIPS 204".to_string(),
            location: location.to_string(),
        }
    }
}

impl fmt::Display for SpecReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.standard, self.location)
    }
}

/// How severe this bug class is, based on real-world impact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational — spec conformance issue with no direct security impact.
    Info,
    /// Low — could cause interoperability issues or minor correctness problems.
    Low,
    /// Medium — correctness bug that could affect security under specific conditions.
    Medium,
    /// High — security-relevant bug (e.g., missing validation, timing leak).
    High,
    /// Critical — directly exploitable (e.g., missing FO check, dead verification code).
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// The outcome of a single test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "status")]
pub enum TestOutcome {
    /// The implementation matched expected behavior.
    Pass,
    /// The implementation diverged from expected behavior.
    Fail {
        /// What was expected.
        expected: String,
        /// What was actually observed.
        actual: String,
        /// Human-readable explanation.
        detail: String,
    },
    /// The test could not be executed (harness error, timeout, etc.).
    Error { message: String },
    /// The test was skipped (e.g., harness doesn't expose the required function).
    Skip { reason: String },
}

impl TestOutcome {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }

    pub fn is_fail(&self) -> bool {
        matches!(self, Self::Fail { .. })
    }
}

/// Metadata describing a single test within a battery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestMeta {
    /// Unique identifier within the battery (e.g., "compress-rounding-boundary-d4-x1664").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// The bug class this test targets.
    pub bug_class: BugClass,
    /// Spec section this test verifies.
    pub spec_ref: SpecReference,
    /// Severity if this test fails.
    pub severity: Severity,
    /// Real-world audit finding that motivated this test, if public.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
}

/// The result of running a single test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub meta: TestMeta,
    pub outcome: TestOutcome,
    /// Time taken in microseconds.
    pub duration_us: u64,
    /// Which parameter set this was run against (e.g., "ML-KEM-768").
    pub parameter_set: String,
}

/// Summary statistics for a test run.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub errors: usize,
    pub skipped: usize,
}

/// The complete report from a Crucible run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Which battery was run (e.g., "ml-kem").
    pub battery: String,
    /// Implementation identifier (from harness).
    pub implementation: String,
    /// All test results.
    pub results: Vec<TestResult>,
    /// Summary counts.
    pub summary: RunSummary,
}

impl Report {
    pub fn new(battery: &str, implementation: &str) -> Self {
        Self {
            battery: battery.to_string(),
            implementation: implementation.to_string(),
            results: Vec::new(),
            summary: RunSummary::default(),
        }
    }

    pub fn add_result(&mut self, result: TestResult) {
        match &result.outcome {
            TestOutcome::Pass => self.summary.passed += 1,
            TestOutcome::Fail { .. } => self.summary.failed += 1,
            TestOutcome::Error { .. } => self.summary.errors += 1,
            TestOutcome::Skip { .. } => self.summary.skipped += 1,
        }
        self.summary.total += 1;
        self.results.push(result);
    }

    /// Render as JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("report serialization cannot fail")
    }

    /// Render as a human-readable summary.
    pub fn to_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Crucible Report: {} — {}\n",
            self.battery, self.implementation
        ));
        out.push_str(&format!(
            "{} tests: {} passed, {} failed, {} errors, {} skipped\n\n",
            self.summary.total,
            self.summary.passed,
            self.summary.failed,
            self.summary.errors,
            self.summary.skipped,
        ));

        // Only show non-pass results in detail.
        for r in &self.results {
            match &r.outcome {
                TestOutcome::Pass => {}
                TestOutcome::Fail {
                    expected,
                    actual,
                    detail,
                } => {
                    out.push_str(&format!(
                        "FAIL [{}] {} ({})\n",
                        r.meta.severity, r.meta.name, r.parameter_set,
                    ));
                    out.push_str(&format!("  Bug class: {}\n", r.meta.bug_class));
                    out.push_str(&format!("  Spec ref:  {}\n", r.meta.spec_ref));
                    if let Some(prov) = &r.meta.provenance {
                        out.push_str(&format!("  Origin:    {prov}\n"));
                    }
                    out.push_str(&format!("  Expected:  {expected}\n"));
                    out.push_str(&format!("  Actual:    {actual}\n"));
                    out.push_str(&format!("  Detail:    {detail}\n"));
                    out.push('\n');
                }
                TestOutcome::Error { message } => {
                    out.push_str(&format!(
                        "ERROR [{}] {} ({}): {message}\n\n",
                        r.meta.severity, r.meta.name, r.parameter_set,
                    ));
                }
                TestOutcome::Skip { reason } => {
                    out.push_str(&format!(
                        "SKIP  {} ({}): {reason}\n",
                        r.meta.name, r.parameter_set,
                    ));
                }
            }
        }

        if self.summary.failed == 0 && self.summary.errors == 0 {
            out.push_str("All tests passed.\n");
        }

        out
    }
}
