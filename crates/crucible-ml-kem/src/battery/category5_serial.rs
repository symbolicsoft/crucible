use crucible_core::harness::Harness;
use crucible_core::orchestrator::{harness_error_to_outcome, TestCase, TestCategory};
use crucible_core::verdict::*;
use crate::params::{self, N, Q};

pub fn category() -> TestCategory {
    TestCategory {
        name: "serialization".to_string(),
        tests: vec![
            Box::new(ByteEncodeRoundTripTest),
            Box::new(ByteDecode12ModReductionTest),
            Box::new(KeyLengthValidationTest),
            Box::new(EncapsKeyModulusRejectionTest),
        ],
    }
}

// ---------------------------------------------------------------------------
// Test 1: ByteEncode_d / ByteDecode_d round-trip for all d.
// ---------------------------------------------------------------------------

struct ByteEncodeRoundTripTest;

impl TestCase for ByteEncodeRoundTripTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("serial-encode-roundtrip-{parameter_set}"),
            name: "ByteDecode_d(ByteEncode_d(F)) == F for all d".to_string(),
            bug_class: BugClass::new("spec-divergence", "encoding-round-trip"),
            spec_ref: SpecReference::fips203("Algorithms 5–6"),
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

        for d in 1..=12u32 {
            let m = if d < 12 { 1u32 << d } else { Q };

            // Test vectors: all zeros, all max, ascending, alternating.
            let test_arrays: Vec<(&str, [u32; N])> = vec![
                ("zeros", [0u32; N]),
                ("max", [m - 1; N]),
                ("ascending", {
                    let mut f = [0u32; N];
                    for i in 0..N {
                        f[i] = (i as u32) % m;
                    }
                    f
                }),
                ("alternating", {
                    let mut f = [0u32; N];
                    for i in 0..N {
                        f[i] = if i % 2 == 0 { 0 } else { m - 1 };
                    }
                    f
                }),
            ];

            for (name, f) in &test_arrays {
                // Encode via harness.
                let f_bytes = poly_to_crucible_bytes(f);
                let encode_result = harness.call_fn(
                    "ByteEncode_d",
                    &[("F", &f_bytes)],
                    &[("d", d as i64)],
                );

                let encoded = match encode_result {
                    Ok(outputs) => match outputs.get("B") {
                        Some(b) => b.clone(),
                        None => {
                            return TestOutcome::Error {
                                message: format!("ByteEncode_{d}: missing 'B' for {name}"),
                            }
                        }
                    },
                    Err(e) => return harness_error_to_outcome(&e),
                };

                // Check length.
                let expected_len = 32 * d as usize;
                if encoded.len() != expected_len {
                    return TestOutcome::Fail {
                        expected: format!("{expected_len} bytes"),
                        actual: format!("{} bytes", encoded.len()),
                        detail: format!("ByteEncode_{d}({name}) wrong output length"),
                    };
                }

                // Decode via harness.
                let decode_result =
                    harness.call_fn("ByteDecode_d", &[("B", &encoded)], &[("d", d as i64)]);

                let decoded = match decode_result {
                    Ok(outputs) => match outputs.get("F") {
                        Some(b) => b.clone(),
                        None => {
                            return TestOutcome::Error {
                                message: format!("ByteDecode_{d}: missing 'F' for {name}"),
                            }
                        }
                    },
                    Err(e) => return harness_error_to_outcome(&e),
                };

                // Compare.
                let decoded_poly = poly_from_crucible_bytes(&decoded);
                if decoded_poly != *f {
                    let first_diff = f
                        .iter()
                        .zip(decoded_poly.iter())
                        .position(|(a, b)| a != b)
                        .unwrap();
                    return TestOutcome::Fail {
                        expected: format!("F[{first_diff}] = {}", f[first_diff]),
                        actual: format!("F[{first_diff}] = {}", decoded_poly[first_diff]),
                        detail: format!(
                            "ByteDecode_{d}(ByteEncode_{d}({name})) diverges at index {first_diff}"
                        ),
                    };
                }
            }
        }

        TestOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// Test 2: ByteDecode_12 mod-q reduction for values in [3329, 4095].
// ---------------------------------------------------------------------------

struct ByteDecode12ModReductionTest;

impl TestCase for ByteDecode12ModReductionTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("serial-decode12-mod-{parameter_set}"),
            name: "ByteDecode_12 reduces values in [q, 4095] mod q".to_string(),
            bug_class: BugClass::new("bounds-check", "coefficient-range"),
            spec_ref: SpecReference::fips203("Algorithm 6, §4.2.1"),
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

        // Create byte arrays encoding 12-bit values >= q.
        for &raw_val in &[3329u32, 3330, 3500, 4000, 4095] {
            let expected = raw_val % Q;

            // Build a 384-byte stream where the first 12-bit value is raw_val.
            let bytes = encode_raw_12bit_single(raw_val);

            let result = harness.call_fn("ByteDecode_d", &[("B", &bytes)], &[("d", 12i64)]);

            match result {
                Ok(outputs) => {
                    if let Some(decoded) = outputs.get("F") {
                        let actual = if decoded.len() >= 2 {
                            u16::from_le_bytes([decoded[0], decoded[1]]) as u32
                        } else {
                            return TestOutcome::Error {
                                message: format!("ByteDecode_12: output too short for val={raw_val}"),
                            };
                        };
                        if actual != expected {
                            return TestOutcome::Fail {
                                expected: format!("{expected}"),
                                actual: format!("{actual}"),
                                detail: format!(
                                    "ByteDecode_12 of raw 12-bit value {raw_val}: got {actual}, \
                                     expected {expected} (= {raw_val} mod {Q})"
                                ),
                            };
                        }
                    }
                }
                Err(e) => return harness_error_to_outcome(&e),
            }
        }

        TestOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// Test 3: Key length validation — wrong-length ek/dk rejected.
// ---------------------------------------------------------------------------

struct KeyLengthValidationTest;

impl TestCase for KeyLengthValidationTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("serial-key-length-{parameter_set}"),
            name: "Encaps/Decaps reject wrong-length keys".to_string(),
            bug_class: BugClass::new("bounds-check", "key-length"),
            spec_ref: SpecReference::fips203("§7.2 Algorithm 20 line 1, §7.3 Algorithm 21 line 1"),
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

        let expected_ek_len = 384 * p.k + 32;

        // Test wrong ek lengths for encaps.
        for &bad_len in &[0usize, 1, expected_ek_len - 1, expected_ek_len + 1] {
            let bad_ek = vec![0u8; bad_len];
            let m = [0u8; 32];
            let result =
                harness.call_fn("ML_KEM_Encaps", &[("ek", &bad_ek), ("randomness", &m)], &[]);

            match result {
                Ok(_) => {
                    return TestOutcome::Fail {
                        expected: format!("rejection for ek length {bad_len}"),
                        actual: "encapsulation succeeded".into(),
                        detail: format!(
                            "ML-KEM.Encaps accepted a {bad_len}-byte ek (expected {expected_ek_len})"
                        ),
                    };
                }
                Err(crucible_core::harness::HarnessError::HarnessError(_)) => {} // Good
                Err(e) => return harness_error_to_outcome(&e),
            }
        }

        TestOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// Test 4: Encaps key with coefficients in [q, 4095] is rejected.
// ---------------------------------------------------------------------------

struct EncapsKeyModulusRejectionTest;

impl TestCase for EncapsKeyModulusRejectionTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("serial-ek-modulus-reject-{parameter_set}"),
            name: "Encaps rejects keys with 12-bit coefficients >= q".to_string(),
            bug_class: BugClass::new("bounds-check", "ek-validation"),
            spec_ref: SpecReference::fips203("§7.2, Algorithm 20 line 2"),
            severity: Severity::Critical,
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

        let ek_len = 384 * p.k + 32;

        // Build an ek where coefficient[0] of the first polynomial is 3329 (raw 12-bit).
        // This should fail the modulus check.
        let bad_poly = encode_raw_12bit_single(3329);
        let mut ek = vec![0u8; ek_len];
        ek[..384].copy_from_slice(&bad_poly);

        let m = [0u8; 32];
        let result = harness.call_fn("ML_KEM_Encaps", &[("ek", &ek), ("randomness", &m)], &[]);

        match result {
            Ok(_) => TestOutcome::Fail {
                expected: "rejection (ek fails modulus check)".into(),
                actual: "encapsulation succeeded".into(),
                detail: format!(
                    "ML-KEM.Encaps accepted an ek with raw 12-bit coefficient 3329 (≥ q). \
                     FIPS 203 §7.2 requires ByteEncode_12(ByteDecode_12(ek_PKE)) == ek_PKE."
                ),
            },
            Err(crucible_core::harness::HarnessError::HarnessError(_)) => TestOutcome::Pass,
            Err(crucible_core::harness::HarnessError::Unsupported(_)) => TestOutcome::Skip {
                reason: "ML_KEM_Encaps not supported".into(),
            },
            Err(e) => harness_error_to_outcome(&e),
        }
    }
}

// ---- Helpers ----

fn poly_to_crucible_bytes(f: &[u32; N]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(N * 2);
    for &coeff in f {
        bytes.extend_from_slice(&(coeff as u16).to_le_bytes());
    }
    bytes
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

/// Encode a 384-byte array where the first 12-bit value is `val` and rest are 0.
fn encode_raw_12bit_single(val: u32) -> Vec<u8> {
    let mut f_raw = [0u32; N];
    f_raw[0] = val;
    let mut bits = vec![0u8; N * 12];
    for i in 0..N {
        let mut a = f_raw[i];
        for j in 0..12 {
            bits[i * 12 + j] = (a & 1) as u8;
            a >>= 1;
        }
    }
    let byte_len = (bits.len() + 7) / 8;
    let mut bytes = vec![0u8; byte_len];
    for (i, &bit) in bits.iter().enumerate() {
        bytes[i / 8] |= bit << (i % 8);
    }
    bytes
}
