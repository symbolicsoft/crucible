use crucible_core::harness::Harness;
use crucible_core::orchestrator::{TestCase, TestCategory, harness_error_to_outcome};
use crucible_core::verdict::*;
use crate::math::compress;
use crate::params::{self, Q};

pub fn category() -> TestCategory {
    TestCategory {
        name: "compression".to_string(),
        tests: vec![
            Box::new(RoundingBoundaryTest),
            Box::new(RoundTripInvariantTest),
            Box::new(BoundaryExhaustionTest),
            Box::new(FloatDivergenceTest),
        ],
    }
}

// ---------------------------------------------------------------------------
// Test 1: Rounding Boundary
// ---------------------------------------------------------------------------

struct RoundingBoundaryTest;

impl TestCase for RoundingBoundaryTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("compress-rounding-boundary-{parameter_set}"),
            name: "Compress_d rounding boundary values".to_string(),
            bug_class: BugClass::new("spec-divergence", "rounding"),
            spec_ref: SpecReference::fips203("§4.2.1, Eq. 4.7"),
            severity: Severity::High,
            provenance: Some("Cryspen ML-KEM decompression rounding bug".to_string()),
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        let p = match params::params_by_name(parameter_set) {
            Some(p) => p,
            None => return TestOutcome::Error { message: format!("unknown parameter set: {parameter_set}") },
        };

        // Test d values relevant to this parameter set: d_u, d_v, and all d in 1..=11.
        let d_values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

        for &d in &d_values {
            let boundaries = compress::find_rounding_boundaries(d);
            if boundaries.is_empty() {
                continue;
            }

            for &(x, expected) in &boundaries {
                // Encode x as a 2-byte little-endian value.
                let x_bytes = (x as u16).to_le_bytes();

                let result = harness.call_fn(
                    "Compress_d",
                    &[("x", &x_bytes)],
                    &[("d", d as i64)],
                );

                match result {
                    Ok(outputs) => {
                        if let Some(out) = outputs.get("y") {
                            let actual = if out.len() >= 2 {
                                u16::from_le_bytes([out[0], out[1]]) as u32
                            } else if out.len() == 1 {
                                out[0] as u32
                            } else {
                                return TestOutcome::Fail {
                                    expected: format!("{expected}"),
                                    actual: "empty output".to_string(),
                                    detail: format!("Compress_{d}({x}): harness returned empty output"),
                                };
                            };

                            if actual != expected {
                                return TestOutcome::Fail {
                                    expected: format!("{expected}"),
                                    actual: format!("{actual}"),
                                    detail: format!(
                                        "Compress_{d}({x}) = {actual}, expected {expected}. \
                                         This is a rounding boundary value where off-by-one \
                                         errors in the ⌈(2^d / q) · x⌋ computation produce wrong results."
                                    ),
                                };
                            }
                        }
                    }
                    Err(e) => return harness_error_to_outcome(&e),
                }
            }
        }

        // Also test d_u and d_v specifically.
        for &d in &[p.du as u32, p.dv as u32] {
            if d > 11 {
                continue;
            }
            let boundaries = compress::find_rounding_boundaries(d);
            for &(x, expected) in &boundaries {
                let x_bytes = (x as u16).to_le_bytes();
                let result = harness.call_fn("Compress_d", &[("x", &x_bytes)], &[("d", d as i64)]);
                match result {
                    Ok(outputs) => {
                        if let Some(out) = outputs.get("y") {
                            let actual = if out.len() >= 2 {
                                u16::from_le_bytes([out[0], out[1]]) as u32
                            } else {
                                out[0] as u32
                            };
                            if actual != expected {
                                return TestOutcome::Fail {
                                    expected: format!("{expected}"),
                                    actual: format!("{actual}"),
                                    detail: format!(
                                        "Compress_{d}({x}) = {actual}, expected {expected} \
                                         (d={d} is d_u or d_v for {parameter_set})"
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
// Test 2: Round-trip invariant
// ---------------------------------------------------------------------------

struct RoundTripInvariantTest;

impl TestCase for RoundTripInvariantTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("compress-round-trip-{parameter_set}"),
            name: "Decompress then Compress preserves input".to_string(),
            bug_class: BugClass::new("spec-divergence", "round-trip"),
            spec_ref: SpecReference::fips203("§4.2.1, properties after Eq. 4.8"),
            severity: Severity::Medium,
            provenance: None,
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        let _p = match params::params_by_name(parameter_set) {
            Some(p) => p,
            None => return TestOutcome::Error { message: format!("unknown parameter set: {parameter_set}") },
        };

        // Verify Compress_d(Decompress_d(y)) = y for all y in ℤ_{2^d}, for d = 1..=11.
        for d in 1..=11u32 {
            let max_y = 1u32 << d;
            // For large d, test a subset (boundaries + random).
            let test_values: Vec<u32> = if d <= 6 {
                (0..max_y).collect()
            } else {
                let mut vals: Vec<u32> = (0..std::cmp::min(64, max_y)).collect();
                vals.push(max_y - 1);
                vals.push(max_y / 2);
                vals.push(max_y / 4);
                vals.dedup();
                vals
            };

            for y in test_values {
                // Decompress
                let y_bytes = (y as u16).to_le_bytes();
                let decomp_result = harness.call_fn(
                    "Decompress_d",
                    &[("y", &y_bytes)],
                    &[("d", d as i64)],
                );
                let x = match decomp_result {
                    Ok(outputs) => {
                        match outputs.get("x") {
                            Some(out) => {
                                if out.len() >= 2 {
                                    u16::from_le_bytes([out[0], out[1]]) as u32
                                } else {
                                    out[0] as u32
                                }
                            }
                            None => return TestOutcome::Error {
                                message: format!("Decompress_d: missing 'x' output for d={d}, y={y}"),
                            },
                        }
                    }
                    Err(e) => return harness_error_to_outcome(&e),
                };

                // Compress
                let x_bytes = (x as u16).to_le_bytes();
                let comp_result = harness.call_fn(
                    "Compress_d",
                    &[("x", &x_bytes)],
                    &[("d", d as i64)],
                );
                match comp_result {
                    Ok(outputs) => {
                        if let Some(out) = outputs.get("y") {
                            let actual = if out.len() >= 2 {
                                u16::from_le_bytes([out[0], out[1]]) as u32
                            } else {
                                out[0] as u32
                            };
                            if actual != y {
                                return TestOutcome::Fail {
                                    expected: format!("{y}"),
                                    actual: format!("{actual}"),
                                    detail: format!(
                                        "Compress_{d}(Decompress_{d}({y})) = {actual}, expected {y}. \
                                         Decompress_{d}({y}) = {x}."
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
// Test 3: Boundary exhaustion
// ---------------------------------------------------------------------------

struct BoundaryExhaustionTest;

impl TestCase for BoundaryExhaustionTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("compress-boundary-exhaustion-{parameter_set}"),
            name: "Compress_d exhaustive test for small d and boundary values".to_string(),
            bug_class: BugClass::new("spec-divergence", "boundary"),
            spec_ref: SpecReference::fips203("§4.2.1"),
            severity: Severity::Medium,
            provenance: None,
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        let _p = match params::params_by_name(parameter_set) {
            Some(p) => p,
            None => return TestOutcome::Error { message: format!("unknown parameter set: {parameter_set}") },
        };

        // For d = 1..=4, test all 3329 values exhaustively.
        for d in 1..=4u32 {
            for x in 0..Q {
                let expected = compress::compress_d(x, d);
                let x_bytes = (x as u16).to_le_bytes();
                let result = harness.call_fn("Compress_d", &[("x", &x_bytes)], &[("d", d as i64)]);

                match result {
                    Ok(outputs) => {
                        if let Some(out) = outputs.get("y") {
                            let actual = if out.len() >= 2 {
                                u16::from_le_bytes([out[0], out[1]]) as u32
                            } else {
                                out[0] as u32
                            };
                            if actual != expected {
                                return TestOutcome::Fail {
                                    expected: format!("{expected}"),
                                    actual: format!("{actual}"),
                                    detail: format!("Compress_{d}({x}) = {actual}, expected {expected}"),
                                };
                            }
                        }
                    }
                    Err(e) => return harness_error_to_outcome(&e),
                }
            }
        }

        // For d = 5..=11, test key boundary values.
        for d in 5..=11u32 {
            let test_values: Vec<u32> = vec![0, 1, Q / 2, Q / 2 + 1, Q - 2, Q - 1];
            for x in test_values {
                let expected = compress::compress_d(x, d);
                let x_bytes = (x as u16).to_le_bytes();
                let result = harness.call_fn("Compress_d", &[("x", &x_bytes)], &[("d", d as i64)]);

                match result {
                    Ok(outputs) => {
                        if let Some(out) = outputs.get("y") {
                            let actual = if out.len() >= 2 {
                                u16::from_le_bytes([out[0], out[1]]) as u32
                            } else {
                                out[0] as u32
                            };
                            if actual != expected {
                                return TestOutcome::Fail {
                                    expected: format!("{expected}"),
                                    actual: format!("{actual}"),
                                    detail: format!("Compress_{d}({x}) = {actual}, expected {expected} (boundary value)"),
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
// Test 4: Float divergence detection
// ---------------------------------------------------------------------------

struct FloatDivergenceTest;

impl TestCase for FloatDivergenceTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("compress-float-divergence-{parameter_set}"),
            name: "Detect floating-point arithmetic in Compress_d".to_string(),
            bug_class: BugClass::new("spec-divergence", "floating-point"),
            spec_ref: SpecReference::fips203("§3.3, no floating-point arithmetic"),
            severity: Severity::High,
            provenance: None,
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        let _p = match params::params_by_name(parameter_set) {
            Some(p) => p,
            None => return TestOutcome::Error { message: format!("unknown parameter set: {parameter_set}") },
        };

        // Find inputs where IEEE 754 f64 gives a different answer than integer arithmetic.
        for d in 1..=11u32 {
            let divergences = compress::find_float_divergences(d);
            if divergences.is_empty() {
                continue;
            }

            // Test each divergence point.
            for &(x, correct, float_val) in &divergences {
                let x_bytes = (x as u16).to_le_bytes();
                let result = harness.call_fn("Compress_d", &[("x", &x_bytes)], &[("d", d as i64)]);

                match result {
                    Ok(outputs) => {
                        if let Some(out) = outputs.get("y") {
                            let actual = if out.len() >= 2 {
                                u16::from_le_bytes([out[0], out[1]]) as u32
                            } else {
                                out[0] as u32
                            };
                            if actual == float_val && actual != correct {
                                return TestOutcome::Fail {
                                    expected: format!("{correct}"),
                                    actual: format!("{actual}"),
                                    detail: format!(
                                        "Compress_{d}({x}) = {actual}, which matches the IEEE 754 f64 result \
                                         but differs from the spec's integer arithmetic result ({correct}). \
                                         FIPS 203 §3.3 forbids floating-point arithmetic."
                                    ),
                                };
                            } else if actual != correct {
                                return TestOutcome::Fail {
                                    expected: format!("{correct}"),
                                    actual: format!("{actual}"),
                                    detail: format!("Compress_{d}({x}) = {actual}, expected {correct}"),
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
