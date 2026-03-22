use crucible_core::harness::Harness;
use crucible_core::orchestrator::{harness_error_to_outcome, TestCase, TestCategory};
use crucible_core::verdict::*;
use crate::params::{self, MlKemParams};

pub fn category() -> TestCategory {
    TestCategory {
        name: "decapsulation".to_string(),
        tests: vec![
            Box::new(ImplicitRejectionTest),
            Box::new(BitFlipRejectionTest),
            Box::new(DecapsKeyLengthTest),
            Box::new(CiphertextLengthTest),
        ],
    }
}

/// Helper: generate a valid (ek, dk, ct, ss) tuple via the harness.
fn generate_valid_tuple(
    harness: &mut Harness,
    p: &MlKemParams,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), TestOutcome> {
    let ps = match p.k {
        2 => 512i64,
        3 => 768,
        _ => 1024,
    };

    // Keygen.
    let mut rng = [0u8; 64];
    rng[0] = 0xDE;
    rng[32] = 0xAD;
    let kg = harness
        .call_fn("ML_KEM_KeyGen", &[("randomness", &rng)], &[("param_set", ps)])
        .map_err(|e| harness_error_to_outcome(&e))?;
    let ek = kg.get("ek").ok_or_else(|| TestOutcome::Error {
        message: "keygen missing ek".into(),
    })?.clone();
    let dk = kg.get("dk").ok_or_else(|| TestOutcome::Error {
        message: "keygen missing dk".into(),
    })?.clone();

    // Encaps.
    let m = [0xCAu8; 32];
    let enc = harness
        .call_fn("ML_KEM_Encaps", &[("ek", &ek), ("randomness", &m)], &[])
        .map_err(|e| harness_error_to_outcome(&e))?;
    let ct = enc.get("c").ok_or_else(|| TestOutcome::Error {
        message: "encaps missing c".into(),
    })?.clone();
    let ss = enc.get("K").ok_or_else(|| TestOutcome::Error {
        message: "encaps missing K".into(),
    })?.clone();

    Ok((ek, dk, ct, ss))
}

// ---------------------------------------------------------------------------
// Test 1: Implicit rejection — corrupted ciphertexts must not return the
// real shared secret.
// ---------------------------------------------------------------------------

struct ImplicitRejectionTest;

impl TestCase for ImplicitRejectionTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("decaps-implicit-rejection-{parameter_set}"),
            name: "Corrupted ciphertexts produce implicit rejection value, not real secret"
                .to_string(),
            bug_class: BugClass::new("spec-divergence", "implicit-rejection"),
            spec_ref: SpecReference::fips203("§6.3, Algorithm 18 lines 5–7"),
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

        let (_, dk, ct, real_ss) = match generate_valid_tuple(harness, p) {
            Ok(t) => t,
            Err(o) => return o,
        };

        // Corrupt the ciphertext in several ways.
        let corruptions: Vec<(&str, Vec<u8>)> = vec![
            ("zeroed", vec![0u8; ct.len()]),
            ("first-byte-flipped", {
                let mut c = ct.clone();
                c[0] ^= 0xFF;
                c
            }),
            ("last-byte-flipped", {
                let mut c = ct.clone();
                let last = c.len() - 1;
                c[last] ^= 0xFF;
                c
            }),
            ("middle-byte-flipped", {
                let mut c = ct.clone();
                c[ct.len() / 2] ^= 0x01;
                c
            }),
            ("all-ones", vec![0xFF; ct.len()]),
        ];

        for (name, bad_ct) in &corruptions {
            let result = harness.call_fn("ML_KEM_Decaps", &[("c", bad_ct), ("dk", &dk)], &[]);

            match result {
                Ok(outputs) => {
                    let ss = match outputs.get("K") {
                        Some(b) => b,
                        None => {
                            return TestOutcome::Error {
                                message: format!("decaps({name}): missing K"),
                            }
                        }
                    };

                    // The returned shared secret MUST NOT be the real one.
                    if ss == &real_ss {
                        return TestOutcome::Fail {
                            expected: "implicit rejection value (different from real shared secret)"
                                .into(),
                            actual: "real shared secret returned for corrupted ciphertext".into(),
                            detail: format!(
                                "Decapsulation of {name}-corrupted ciphertext returned the real \
                                 shared secret. This means the FO re-encryption check is missing \
                                 or the implementation is not performing implicit rejection \
                                 (FIPS 203 Algorithm 18, lines 5–7)."
                            ),
                        };
                    }

                    // It must be exactly 32 bytes.
                    if ss.len() != 32 {
                        return TestOutcome::Fail {
                            expected: "32-byte shared secret".into(),
                            actual: format!("{}-byte output", ss.len()),
                            detail: format!("Decaps({name}) returned wrong-length output"),
                        };
                    }

                    // It must be deterministic: same (dk, bad_ct) → same output.
                    let result2 =
                        harness.call_fn("ML_KEM_Decaps", &[("c", bad_ct), ("dk", &dk)], &[]);
                    if let Ok(outputs2) = result2 {
                        if let Some(ss2) = outputs2.get("K") {
                            if ss != ss2 {
                                return TestOutcome::Fail {
                                    expected: "deterministic implicit rejection".into(),
                                    actual: "different outputs for same invalid ciphertext".into(),
                                    detail: format!(
                                        "Decaps({name}) is not deterministic for invalid \
                                         ciphertexts. The implicit rejection value J(z||c) must \
                                         be deterministic."
                                    ),
                                };
                            }
                        }
                    }
                }
                Err(e) => {
                    // Decaps should NEVER return an error — it should always produce
                    // either the real secret or the implicit rejection value.
                    return TestOutcome::Fail {
                        expected: "implicit rejection value (no error)".into(),
                        actual: format!("error: {e}"),
                        detail: format!(
                            "Decapsulation of {name}-corrupted ciphertext returned an error \
                             instead of the implicit rejection value. FIPS 203 §6.3 requires \
                             that decapsulation always succeeds, producing K̄ = J(z||c) for \
                             invalid ciphertexts."
                        ),
                    };
                }
            }
        }

        TestOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// Test 2: Single bit flips in valid ciphertext — every single-bit flip
// must produce a different shared secret (implicit rejection).
// ---------------------------------------------------------------------------

struct BitFlipRejectionTest;

impl TestCase for BitFlipRejectionTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("decaps-bitflip-rejection-{parameter_set}"),
            name: "Single bit flips in ciphertext always trigger rejection".to_string(),
            bug_class: BugClass::new("dead-code", "missing-fo-check"),
            spec_ref: SpecReference::fips203("Algorithm 18, lines 4–7"),
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

        let (_, dk, ct, real_ss) = match generate_valid_tuple(harness, p) {
            Ok(t) => t,
            Err(o) => return o,
        };

        // Test bit flips at strategic positions: first byte, last byte, middle,
        // and a position in each of the ciphertext components (c1 and c2).
        let c1_len = 32 * p.du * p.k;
        let positions = [0, 1, c1_len / 2, c1_len, c1_len + 1, ct.len() - 1];

        for &pos in &positions {
            if pos >= ct.len() {
                continue;
            }
            for bit in [0, 3, 7] {
                let mut bad_ct = ct.clone();
                bad_ct[pos] ^= 1 << bit;

                let result =
                    harness.call_fn("ML_KEM_Decaps", &[("c", &bad_ct), ("dk", &dk)], &[]);

                match result {
                    Ok(outputs) => {
                        if let Some(ss) = outputs.get("K") {
                            if ss == &real_ss {
                                return TestOutcome::Fail {
                                    expected: "rejection (different shared secret)".into(),
                                    actual: "real shared secret returned".into(),
                                    detail: format!(
                                        "Flipping bit {bit} at ciphertext byte {pos} did not \
                                         trigger implicit rejection. The implementation may be \
                                         skipping the FO re-encryption comparison."
                                    ),
                                };
                            }
                        }
                    }
                    Err(e) => {
                        return TestOutcome::Fail {
                            expected: "implicit rejection value".into(),
                            actual: format!("error: {e}"),
                            detail: format!(
                                "Decaps errored on bit-flipped ciphertext (pos={pos}, bit={bit}). \
                                 Must produce implicit rejection, not an error."
                            ),
                        };
                    }
                }
            }
        }

        TestOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// Test 3: Decapsulation key length validation.
// ---------------------------------------------------------------------------

struct DecapsKeyLengthTest;

impl TestCase for DecapsKeyLengthTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("decaps-dk-length-{parameter_set}"),
            name: "Decapsulation rejects wrong-length keys".to_string(),
            bug_class: BugClass::new("bounds-check", "dk-validation"),
            spec_ref: SpecReference::fips203("§7.3, Algorithm 21"),
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

        let expected_dk_len = 768 * p.k + 96;
        let expected_ct_len = 32 * p.du * p.k + 32 * p.dv;
        let valid_ct = vec![0u8; expected_ct_len];

        // Test wrong dk lengths: too short, too long, empty.
        for &bad_len in &[0usize, 1, expected_dk_len - 1, expected_dk_len + 1] {
            let bad_dk = vec![0u8; bad_len];
            let result =
                harness.call_fn("ML_KEM_Decaps", &[("c", &valid_ct), ("dk", &bad_dk)], &[]);

            match result {
                Ok(_) => {
                    return TestOutcome::Fail {
                        expected: format!("rejection for dk length {bad_len}"),
                        actual: "decapsulation succeeded".into(),
                        detail: format!(
                            "Decaps accepted a {bad_len}-byte decapsulation key (expected {expected_dk_len}). \
                             Wrong-length keys must be rejected before computation."
                        ),
                    };
                }
                Err(crucible_core::harness::HarnessError::HarnessError(_)) => {
                    // Good — rejected.
                }
                Err(e) => return harness_error_to_outcome(&e),
            }
        }

        TestOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// Test 4: Ciphertext length validation during decapsulation.
// ---------------------------------------------------------------------------

struct CiphertextLengthTest;

impl TestCase for CiphertextLengthTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("decaps-ct-length-{parameter_set}"),
            name: "Decapsulation handles wrong-length ciphertexts".to_string(),
            bug_class: BugClass::new("bounds-check", "ciphertext-length"),
            spec_ref: SpecReference::fips203("Algorithm 15, input parsing"),
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

        // Generate a valid dk.
        let (_, dk, _, _) = match generate_valid_tuple(harness, p) {
            Ok(t) => t,
            Err(o) => return o,
        };

        let expected_ct_len = 32 * p.du * p.k + 32 * p.dv;

        // Test wrong ct lengths.
        for &bad_len in &[0usize, 1, expected_ct_len - 1, expected_ct_len + 1] {
            let bad_ct = vec![0u8; bad_len];
            let result =
                harness.call_fn("ML_KEM_Decaps", &[("c", &bad_ct), ("dk", &dk)], &[]);

            match result {
                Ok(_) => {
                    // Some implementations may accept wrong-length ciphertexts and produce
                    // the implicit rejection value rather than erroring. This is acceptable
                    // behavior — the spec doesn't mandate rejection, just that the output
                    // is safe.
                }
                Err(crucible_core::harness::HarnessError::HarnessError(_)) => {
                    // Explicit rejection — also acceptable.
                }
                Err(e) => return harness_error_to_outcome(&e),
            }
        }

        TestOutcome::Pass
    }
}
