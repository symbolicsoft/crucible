//! Timing measurement and statistical analysis for constant-time testing.
//!
//! Provides Welch's t-test to compare timing distributions across input classes
//! (e.g., valid vs. invalid ciphertexts during decapsulation).

use serde::{Deserialize, Serialize};

/// A collection of timing samples for statistical analysis.
#[derive(Debug, Clone, Default)]
pub struct TimingSamples {
    samples: Vec<f64>,
}

impl TimingSamples {
    pub fn new() -> Self {
        Self {
            samples: Vec::new(),
        }
    }

    pub fn add(&mut self, duration_ns: u64) {
        self.samples.push(duration_ns as f64);
    }

    pub fn count(&self) -> usize {
        self.samples.len()
    }

    pub fn mean(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        self.samples.iter().sum::<f64>() / self.samples.len() as f64
    }

    pub fn variance(&self) -> f64 {
        if self.samples.len() < 2 {
            return 0.0;
        }
        let mean = self.mean();
        let n = self.samples.len() as f64;
        self.samples.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0)
    }

    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }
}

/// Result of Welch's t-test comparing two timing distributions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelchResult {
    /// The t-statistic. Large absolute values indicate significant timing differences.
    pub t_statistic: f64,
    /// Degrees of freedom (Welch-Satterthwaite approximation).
    pub degrees_of_freedom: f64,
    /// Whether the difference is statistically significant at the given threshold.
    /// Uses a conservative threshold: |t| > 4.5 (well beyond p < 0.001 for large n).
    pub significant: bool,
    /// Mean of class A in nanoseconds.
    pub mean_a_ns: f64,
    /// Mean of class B in nanoseconds.
    pub mean_b_ns: f64,
    /// Number of samples in class A.
    pub n_a: usize,
    /// Number of samples in class B.
    pub n_b: usize,
}

/// Perform Welch's t-test on two sets of timing samples.
///
/// Returns None if either sample set has fewer than 2 measurements.
///
/// The significance threshold of |t| > 4.5 is deliberately conservative
/// to reduce false positives. With 10,000+ samples per class, this
/// corresponds to p << 0.001.
pub fn welch_t_test(a: &TimingSamples, b: &TimingSamples) -> Option<WelchResult> {
    let n_a = a.count();
    let n_b = b.count();
    if n_a < 2 || n_b < 2 {
        return None;
    }

    let mean_a = a.mean();
    let mean_b = b.mean();
    let var_a = a.variance();
    let var_b = b.variance();
    let n_a_f = n_a as f64;
    let n_b_f = n_b as f64;

    let se_a = var_a / n_a_f;
    let se_b = var_b / n_b_f;
    let se_sum = se_a + se_b;

    if se_sum == 0.0 {
        // Zero variance in both — they're identical.
        return Some(WelchResult {
            t_statistic: 0.0,
            degrees_of_freedom: (n_a + n_b - 2) as f64,
            significant: false,
            mean_a_ns: mean_a,
            mean_b_ns: mean_b,
            n_a,
            n_b,
        });
    }

    let t = (mean_a - mean_b) / se_sum.sqrt();

    // Welch-Satterthwaite degrees of freedom.
    let df = se_sum.powi(2)
        / (se_a.powi(2) / (n_a_f - 1.0) + se_b.powi(2) / (n_b_f - 1.0));

    Some(WelchResult {
        t_statistic: t,
        degrees_of_freedom: df,
        significant: t.abs() > 4.5,
        mean_a_ns: mean_a,
        mean_b_ns: mean_b,
        n_a,
        n_b,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_samples_not_significant() {
        let mut a = TimingSamples::new();
        let mut b = TimingSamples::new();
        for _ in 0..100 {
            a.add(1000);
            b.add(1000);
        }
        let result = welch_t_test(&a, &b).unwrap();
        assert!(!result.significant);
        assert_eq!(result.t_statistic, 0.0);
    }

    #[test]
    fn different_samples_significant() {
        let mut a = TimingSamples::new();
        let mut b = TimingSamples::new();
        for i in 0..1000 {
            a.add(1000 + (i % 10));
            b.add(2000 + (i % 10));
        }
        let result = welch_t_test(&a, &b).unwrap();
        assert!(result.significant);
        assert!(result.t_statistic.abs() > 4.5);
    }

    #[test]
    fn too_few_samples() {
        let mut a = TimingSamples::new();
        let mut b = TimingSamples::new();
        a.add(100);
        b.add(200);
        assert!(welch_t_test(&a, &b).is_none());
    }
}
