use crucible_core::harness::Harness;
use crucible_core::orchestrator::{harness_error_to_outcome, TestCase, TestCategory};
use crucible_core::verdict::*;
use crate::math::sampling;
use crate::params::{self, N, Q};

pub fn category() -> TestCategory {
    TestCategory {
        name: "sampling".to_string(),
        tests: vec![
            Box::new(CbdOutputRangeTest),
            Box::new(CbdDeterminismTest),
            Box::new(SampleNttDeterminismTest),
            Box::new(SampleNttRejectsAboveQTest),
        ],
    }
}

fn poly_from_crucible_bytes(bytes: &[u8]) -> [u32; N] {
    let mut f = [0u32; N];
    for i in 0..N {
        if 2 * i + 1 < bytes.len() {
            f[i] = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]) as u32;
        }
    }
    f
}

// ---------------------------------------------------------------------------
// Test 1: CBD output is in correct range for each eta.
// ---------------------------------------------------------------------------

struct CbdOutputRangeTest;

impl TestCase for CbdOutputRangeTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("sampling-cbd-range-{parameter_set}"),
            name: "SamplePolyCBD output coefficients in correct range".to_string(),
            bug_class: BugClass::new("spec-divergence", "cbd"),
            spec_ref: SpecReference::fips203("Algorithm 8"),
            severity: Severity::High,
            provenance: None,
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        let p = match params::params_by_name(parameter_set) {
            Some(p) => p,
            None => {
                return TestOutcome::Error {
                    message: format!("unknown: {parameter_set}"),
                }
            }
        };

        // Test with several seed values for each eta used by this parameter set.
        for &eta in &[p.eta1, p.eta2] {
            let input_len = 64 * eta;

            // Test with different seed patterns.
            for seed_byte in [0x00u8, 0x55, 0xAA, 0xFF] {
                let input = vec![seed_byte; input_len];
                let result = harness.call_fn(
                    "SamplePolyCBD",
                    &[("B", &input)],
                    &[("eta", eta as i64)],
                );

                match result {
                    Ok(outputs) => {
                        let f_bytes = match outputs.get("f") {
                            Some(b) => b,
                            None => {
                                return TestOutcome::Error {
                                    message: format!("SamplePolyCBD: missing 'f' for eta={eta}"),
                                }
                            }
                        };
                        let f = poly_from_crucible_bytes(f_bytes);

                        // Each coefficient must be in {0, 1, ..., eta, q-eta, ..., q-1}.
                        for (i, &coeff) in f.iter().enumerate() {
                            let in_range = coeff <= eta as u32 || coeff >= Q - eta as u32;
                            if !in_range {
                                return TestOutcome::Fail {
                                    expected: format!(
                                        "coefficient in [0,{eta}] ∪ [{},{}]",
                                        Q - eta as u32,
                                        Q - 1
                                    ),
                                    actual: format!("f[{i}] = {coeff}"),
                                    detail: format!(
                                        "SamplePolyCBD_{eta}(seed=0x{seed_byte:02x}) produced \
                                         coefficient {coeff} at index {i}, outside the valid range."
                                    ),
                                };
                            }
                        }
                    }
                    Err(e) => return harness_error_to_outcome(&e),
                }
            }
        }

        TestOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// Test 2: CBD is deterministic — same input → same output.
// ---------------------------------------------------------------------------

struct CbdDeterminismTest;

impl TestCase for CbdDeterminismTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("sampling-cbd-determinism-{parameter_set}"),
            name: "SamplePolyCBD is deterministic".to_string(),
            bug_class: BugClass::new("spec-divergence", "cbd"),
            spec_ref: SpecReference::fips203("Algorithm 8"),
            severity: Severity::High,
            provenance: None,
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        let p = match params::params_by_name(parameter_set) {
            Some(p) => p,
            None => {
                return TestOutcome::Error {
                    message: format!("unknown: {parameter_set}"),
                }
            }
        };

        for &eta in &[p.eta1, p.eta2] {
            let input = vec![0x42u8; 64 * eta];

            let r1 = match harness.call_fn("SamplePolyCBD", &[("B", &input)], &[("eta", eta as i64)]) {
                Ok(o) => o.get("f").cloned(),
                Err(e) => return harness_error_to_outcome(&e),
            };
            let r2 = match harness.call_fn("SamplePolyCBD", &[("B", &input)], &[("eta", eta as i64)]) {
                Ok(o) => o.get("f").cloned(),
                Err(e) => return harness_error_to_outcome(&e),
            };

            if r1 != r2 {
                return TestOutcome::Fail {
                    expected: "identical outputs for identical inputs".into(),
                    actual: "different outputs".into(),
                    detail: format!("SamplePolyCBD_{eta} is not deterministic"),
                };
            }

            // Also verify against our reference.
            let ref_output = sampling::sample_poly_cbd(&input, eta);
            if let Some(harness_bytes) = &r1 {
                let harness_poly = poly_from_crucible_bytes(harness_bytes);
                if harness_poly != ref_output {
                    let first_diff = harness_poly
                        .iter()
                        .zip(ref_output.iter())
                        .position(|(a, b)| a != b)
                        .unwrap();
                    return TestOutcome::Fail {
                        expected: format!("f[{first_diff}] = {}", ref_output[first_diff]),
                        actual: format!("f[{first_diff}] = {}", harness_poly[first_diff]),
                        detail: format!(
                            "SamplePolyCBD_{eta} diverges from reference at index {first_diff}"
                        ),
                    };
                }
            }
        }

        TestOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// Test 3: SampleNTT is deterministic for a given 34-byte seed.
// ---------------------------------------------------------------------------

struct SampleNttDeterminismTest;

impl TestCase for SampleNttDeterminismTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("sampling-ntt-determinism-{parameter_set}"),
            name: "SampleNTT is deterministic for a given seed".to_string(),
            bug_class: BugClass::new("spec-divergence", "rejection-sampling"),
            spec_ref: SpecReference::fips203("Algorithm 7"),
            severity: Severity::High,
            provenance: None,
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        if params::params_by_name(parameter_set).is_none() {
            return TestOutcome::Error {
                message: format!("unknown: {parameter_set}"),
            };
        }

        // 34-byte seed: 32-byte rho + 2 index bytes.
        let seed = [0x37u8; 34];

        let r1 = match harness.call_fn("SampleNTT", &[("B", &seed)], &[]) {
            Ok(o) => o.get("a_hat").cloned(),
            Err(e) => return harness_error_to_outcome(&e),
        };
        let r2 = match harness.call_fn("SampleNTT", &[("B", &seed)], &[]) {
            Ok(o) => o.get("a_hat").cloned(),
            Err(e) => return harness_error_to_outcome(&e),
        };

        if r1 != r2 {
            return TestOutcome::Fail {
                expected: "identical outputs for identical seed".into(),
                actual: "different outputs".into(),
                detail: "SampleNTT is not deterministic".into(),
            };
        }

        // Check all coefficients are in [0, q-1].
        if let Some(bytes) = &r1 {
            let poly = poly_from_crucible_bytes(bytes);
            for (i, &coeff) in poly.iter().enumerate() {
                if coeff >= Q {
                    return TestOutcome::Fail {
                        expected: format!("coefficient < {Q}"),
                        actual: format!("a_hat[{i}] = {coeff}"),
                        detail: format!(
                            "SampleNTT produced coefficient {coeff} ≥ q at index {i}"
                        ),
                    };
                }
            }
        }

        TestOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// Test 4: SampleNTT correctly rejects values >= q in the XOF stream.
// ---------------------------------------------------------------------------

struct SampleNttRejectsAboveQTest;

impl TestCase for SampleNttRejectsAboveQTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("sampling-ntt-rejection-{parameter_set}"),
            name: "SampleNTT rejects 12-bit values >= q from XOF".to_string(),
            bug_class: BugClass::new("spec-divergence", "rejection-sampling"),
            spec_ref: SpecReference::fips203("Algorithm 7"),
            severity: Severity::High,
            provenance: None,
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        if params::params_by_name(parameter_set).is_none() {
            return TestOutcome::Error {
                message: format!("unknown: {parameter_set}"),
            };
        }

        // Use several different seeds and verify all output coefficients < q.
        // Seeds that produce high-valued XOF bytes will exercise rejection sampling.
        for seed_val in [0x00u8, 0xFF, 0x80, 0x42] {
            let mut seed = [seed_val; 34];
            seed[32] = 0; // index bytes
            seed[33] = 0;

            let result = match harness.call_fn("SampleNTT", &[("B", &seed.to_vec())], &[]) {
                Ok(o) => match o.get("a_hat") {
                    Some(b) => b.clone(),
                    None => {
                        return TestOutcome::Error {
                            message: "SampleNTT: missing 'a_hat'".into(),
                        }
                    }
                },
                Err(e) => return harness_error_to_outcome(&e),
            };

            let poly = poly_from_crucible_bytes(&result);

            // Exactly 256 coefficients, all < q.
            for (i, &coeff) in poly.iter().enumerate() {
                if coeff >= Q {
                    return TestOutcome::Fail {
                        expected: format!("all coefficients < {Q}"),
                        actual: format!("a_hat[{i}] = {coeff}"),
                        detail: format!(
                            "SampleNTT with seed 0x{seed_val:02x} produced coefficient \
                             {coeff} ≥ q at index {i}. Rejection sampling is broken."
                        ),
                    };
                }
            }
        }

        TestOutcome::Pass
    }
}
