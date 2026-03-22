use crucible_core::harness::Harness;
use crucible_core::orchestrator::{TestCase, TestCategory, harness_error_to_outcome};
use crucible_core::verdict::*;
use crate::math::encode;
use crate::params::{self, N, Q};

pub fn category() -> TestCategory {
    TestCategory {
        name: "bounds".to_string(),
        tests: vec![
            Box::new(OverBoundCoefficientTest),
            Box::new(EkModulusCheckTest),
            Box::new(BitWidthBoundaryTest),
        ],
    }
}

// ---------------------------------------------------------------------------
// Test 1: Over-bound coefficient injection
// ---------------------------------------------------------------------------

struct OverBoundCoefficientTest;

impl TestCase for OverBoundCoefficientTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("bounds-overbound-coeff-{parameter_set}"),
            name: "ByteDecode_12 correctly reduces coefficients ≥ q".to_string(),
            bug_class: BugClass::new("bounds-check", "coefficient-range"),
            spec_ref: SpecReference::fips203("Algorithm 6, §4.2.1"),
            severity: Severity::High,
            provenance: None,
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        if params::params_by_name(parameter_set).is_none() {
            return TestOutcome::Error { message: format!("unknown parameter set: {parameter_set}") };
        }

        // Test values that are valid 12-bit integers but >= q = 3329.
        let test_values: Vec<u32> = vec![3329, 3330, 3500, 4000, 4095];

        for &val in &test_values {
            // Build a 384-byte array where the first coefficient encodes `val`.
            let mut f_raw = [0u32; N];
            f_raw[0] = val;
            let encoded = encode_raw_12bit(&f_raw);

            let result = harness.call_fn("ByteDecode_d", &[("B", &encoded)], &[("d", 12)]);

            match result {
                Ok(outputs) => {
                    if let Some(decoded_bytes) = outputs.get("F") {
                        // First coefficient should be val % q.
                        let expected = val % Q;
                        let actual = if decoded_bytes.len() >= 2 {
                            u16::from_le_bytes([decoded_bytes[0], decoded_bytes[1]]) as u32
                        } else {
                            return TestOutcome::Error {
                                message: format!("ByteDecode_12 output too short for val={val}"),
                            };
                        };

                        if actual != expected {
                            return TestOutcome::Fail {
                                expected: format!("{expected}"),
                                actual: format!("{actual}"),
                                detail: format!(
                                    "ByteDecode_12 of 12-bit value {val}: got {actual}, \
                                     expected {expected} (= {val} mod {Q}). \
                                     The spec requires reduction mod q for d=12."
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
// Test 2: Encapsulation key modulus check
// ---------------------------------------------------------------------------

struct EkModulusCheckTest;

impl TestCase for EkModulusCheckTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("bounds-ek-modulus-{parameter_set}"),
            name: "Encapsulation key rejects coefficients in [q, 4095]".to_string(),
            bug_class: BugClass::new("bounds-check", "ek-validation"),
            spec_ref: SpecReference::fips203("§7.2, Algorithm 20 line 2"),
            severity: Severity::Critical,
            provenance: None,
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        let p = match params::params_by_name(parameter_set) {
            Some(p) => p,
            None => return TestOutcome::Error { message: format!("unknown parameter set: {parameter_set}") },
        };

        // Construct a valid-looking encapsulation key with one coefficient = 3329
        // in the polynomial portion (first 384*k bytes).
        let ek_pke_len = 384 * p.k;
        let ek_len = ek_pke_len + 32; // 384*k bytes of polynomials + 32 bytes of ρ

        // Build an ek where the first polynomial has coefficient[0] = 3329 (invalid).
        let mut f_raw = [0u32; N];
        f_raw[0] = 3329; // This is q, which after ByteDecode_12 reduces to 0.
        let bad_poly_bytes = encode_raw_12bit(&f_raw);

        let mut ek = vec![0u8; ek_len];
        ek[..384].copy_from_slice(&bad_poly_bytes);
        // Rest is zeros (valid polynomials) + 32-byte ρ (zeros).

        // The modulus check is: ByteEncode_12(ByteDecode_12(ek_PKE)) == ek_PKE
        // Since coefficient 0 is encoded as 3329 (raw 12-bit), but ByteDecode_12 reduces
        // it to 0, then ByteEncode_12 will output 0 (not 3329). So the check should fail.
        let check_passes = encode::ek_modulus_check(&ek[..ek_pke_len]);
        assert!(!check_passes, "our reference should detect the bad ek");

        // Ask the harness to validate the ek via encapsulation.
        // A conforming implementation should reject this key.
        let result = harness.call_fn(
            "ML_KEM_Encaps",
            &[("ek", &ek)],
            &[],
        );

        match result {
            Ok(_outputs) => {
                // If encapsulation succeeded, the implementation didn't check the key.
                TestOutcome::Fail {
                    expected: "rejection (encapsulation key fails modulus check)".to_string(),
                    actual: "encapsulation succeeded".to_string(),
                    detail: format!(
                        "ML-KEM.Encaps accepted an encapsulation key with a 12-bit coefficient \
                         of 3329 (≥ q). FIPS 203 §7.2 requires the check \
                         ByteEncode_12(ByteDecode_12(ek_PKE)) == ek_PKE."
                    ),
                }
            }
            Err(crucible_core::harness::HarnessError::HarnessError(_msg)) => {
                // The harness reported an error, meaning the key was rejected. Good.
                TestOutcome::Pass
            }
            Err(crucible_core::harness::HarnessError::Unsupported(_)) => {
                TestOutcome::Skip {
                    reason: "harness does not support ML_KEM_Encaps".to_string(),
                }
            }
            Err(e) => harness_error_to_outcome(&e),
        }
    }
}

// ---------------------------------------------------------------------------
// Test 3: Bit-width boundary
// ---------------------------------------------------------------------------

struct BitWidthBoundaryTest;

impl TestCase for BitWidthBoundaryTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("bounds-bitwidth-boundary-{parameter_set}"),
            name: "ByteEncode/Decode handles 12-bit boundary values at every position".to_string(),
            bug_class: BugClass::new("spec-divergence", "bit-boundary"),
            spec_ref: SpecReference::fips203("Algorithms 5–6"),
            severity: Severity::Medium,
            provenance: None,
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        if params::params_by_name(parameter_set).is_none() {
            return TestOutcome::Error { message: format!("unknown parameter set: {parameter_set}") };
        }

        // Test ByteEncode_12 / ByteDecode_12 round-trip with boundary values
        // at various positions in the polynomial.
        let boundary_values = [0u32, 1, 3327, 3328]; // max valid value is q-1 = 3328

        for &val in &boundary_values {
            for pos in [0, 1, 127, 128, 254, 255] {
                let mut f = [0u32; N];
                f[pos] = val;
                let f_bytes = encode::byte_encode(&f, 12);

                let result = harness.call_fn("ByteDecode_d", &[("B", &f_bytes)], &[("d", 12)]);

                match result {
                    Ok(outputs) => {
                        if let Some(decoded_bytes) = outputs.get("F") {
                            // Decode and check position `pos`.
                            if decoded_bytes.len() < (pos + 1) * 2 {
                                return TestOutcome::Error {
                                    message: format!("ByteDecode_12 output too short"),
                                };
                            }
                            let actual = u16::from_le_bytes([
                                decoded_bytes[2 * pos],
                                decoded_bytes[2 * pos + 1],
                            ]) as u32;

                            if actual != val {
                                return TestOutcome::Fail {
                                    expected: format!("{val}"),
                                    actual: format!("{actual}"),
                                    detail: format!(
                                        "ByteDecode_12(ByteEncode_12(f))[{pos}] = {actual}, \
                                         expected {val}. 12-bit boundary value at position {pos} \
                                         was not preserved across encode/decode."
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
// Helpers
// ---------------------------------------------------------------------------

/// Encode 256 raw 12-bit values into 384 bytes without mod-q reduction.
/// This is for constructing test inputs that deliberately contain values ≥ q.
fn encode_raw_12bit(f: &[u32; N]) -> Vec<u8> {
    let mut bits = vec![0u8; N * 12];
    for i in 0..N {
        let mut a = f[i];
        for j in 0..12 {
            bits[i * 12 + j] = (a & 1) as u8;
            a >>= 1;
        }
    }
    // bits_to_bytes
    let byte_len = (bits.len() + 7) / 8;
    let mut bytes = vec![0u8; byte_len];
    for (i, &bit) in bits.iter().enumerate() {
        bytes[i / 8] |= bit << (i % 8);
    }
    bytes
}
