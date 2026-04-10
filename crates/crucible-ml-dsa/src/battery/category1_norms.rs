//! Category 1: Norm Checks and Hint Validation.
//!
//! Tests that verify the implementation correctly enforces z-norm bounds,
//! rejects malformed hints, and handles basic sign/verify round-trips.

use crucible_core::harness::Harness;
use crucible_core::orchestrator::{harness_error_to_outcome, TestCase, TestCategory};
use crucible_core::verdict::*;
use crate::params::{self, MlDsaParams, expected_pk_len, expected_sk_len, expected_sig_len};

pub fn category() -> TestCategory {
    TestCategory {
        name: "norms".to_string(),
        tests: vec![
            Box::new(VerifierZNormTest),
            Box::new(HintBitUnpackMalformedTest),
            Box::new(HintLeftoverNonZeroTest),
            Box::new(SignVerifyRoundTripTest),
        ],
    }
}

/// Extract the numeric suffix from a parameter set name for the harness param.
/// "ML-DSA-44" -> 44, "ML-DSA-65" -> 65, "ML-DSA-87" -> 87.
fn param_set_id(p: &MlDsaParams) -> i64 {
    match p.name {
        "ML-DSA-44" => 44,
        "ML-DSA-65" => 65,
        "ML-DSA-87" => 87,
        _ => 0,
    }
}

/// Helper: generate a valid (pk, sk, sig, msg) tuple via the harness.
fn generate_valid_tuple(
    harness: &mut Harness,
    p: &MlDsaParams,
    seed: u8,
    msg: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), TestOutcome> {
    let ps = param_set_id(p);
    let xi = [seed; 32];
    let rnd = [0u8; 32]; // deterministic signing

    let kg = harness
        .call_fn("ML_DSA_KeyGen", &[("seed", &xi)], &[("param_set", ps)])
        .map_err(|e| harness_error_to_outcome(&e))?;
    let pk = kg.get("pk").ok_or_else(|| TestOutcome::Error {
        message: "keygen missing pk".into(),
    })?.clone();
    let sk = kg.get("sk").ok_or_else(|| TestOutcome::Error {
        message: "keygen missing sk".into(),
    })?.clone();

    let exp_pk = expected_pk_len(p);
    if pk.len() != exp_pk {
        return Err(TestOutcome::Error {
            message: format!(
                "harness returned {}-byte pk for {} (expected {exp_pk} bytes)",
                pk.len(), p.name
            ),
        });
    }
    let exp_sk = expected_sk_len(p);
    if sk.len() != exp_sk {
        return Err(TestOutcome::Error {
            message: format!(
                "harness returned {}-byte sk for {} (expected {exp_sk} bytes)",
                sk.len(), p.name
            ),
        });
    }

    let sign_result = harness
        .call_fn(
            "ML_DSA_Sign",
            &[("sk", &sk), ("message", msg), ("rnd", &rnd)],
            &[],
        )
        .map_err(|e| harness_error_to_outcome(&e))?;
    let sig = sign_result.get("signature").ok_or_else(|| TestOutcome::Error {
        message: "sign missing signature".into(),
    })?.clone();

    let exp_sig = expected_sig_len(p);
    if sig.len() != exp_sig {
        return Err(TestOutcome::Error {
            message: format!(
                "harness returned {}-byte signature for {} (expected {exp_sig} bytes)",
                sig.len(), p.name
            ),
        });
    }

    Ok((pk, sk, sig))
}

// ---------------------------------------------------------------------------
// Test 1: Verifier z-norm bound
// ---------------------------------------------------------------------------

struct VerifierZNormTest;

impl TestCase for VerifierZNormTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("norms-z-norm-bound-{parameter_set}"),
            name: "Verify rejects signature with z-norm at/above gamma1 - beta".to_string(),
            bug_class: BugClass::new("bounds-check", "z-norm"),
            spec_ref: SpecReference::fips204("Algorithm 8, line 13"),
            severity: Severity::Critical,
            provenance: None,
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        let p = match params::params_by_name(parameter_set) {
            Some(p) => p,
            None => return TestOutcome::Error {
                message: format!("unknown parameter set: {parameter_set}"),
            },
        };

        let msg = b"z-norm test message";

        // Generate a valid signature.
        let (pk, _sk, sig) = match generate_valid_tuple(harness, p, 0x11, msg) {
            Ok(t) => t,
            Err(o) => return o,
        };

        // Corrupt the z component of the signature to push its infinity norm
        // to at or above gamma1 - beta. The signature layout is:
        //   c_tilde (lambda/4 bytes) || z (l * z_pack_size bytes) || h (omega + k bytes)
        //
        // We'll flip bits in the first z coefficient to create an extreme value.
        // A correct verifier must reject this.
        let c_tilde_len = p.lambda / 4;
        let gamma1_bits = if p.gamma1 == (1 << 17) { 18 } else { 20 };
        let z_pack_size = 32 * gamma1_bits;

        // Create a corrupted signature: set the first few bytes of the z portion
        // to all 0xFF, which encodes a z coefficient near the maximum range.
        let mut bad_sig = sig.clone();
        if bad_sig.len() > c_tilde_len + 2 {
            // Overwrite first bytes of z portion with high values.
            for i in 0..std::cmp::min(4, z_pack_size) {
                bad_sig[c_tilde_len + i] = 0xFF;
            }
        }

        let ps = param_set_id(p);
        let _ = ps; // param_set is embedded in the key

        let result = harness.call_fn(
            "ML_DSA_Verify",
            &[("pk", &pk), ("message", msg), ("sigma", &bad_sig)],
            &[],
        );

        match result {
            Ok(outputs) => {
                if let Some(valid) = outputs.get("valid") {
                    if valid.len() >= 1 && valid[0] == 0x01 {
                        return TestOutcome::Fail {
                            expected: "rejection (valid = 0x00)".into(),
                            actual: "verification succeeded (valid = 0x01)".into(),
                            detail: format!(
                                "ML_DSA_Verify accepted a signature with corrupted z component. \
                                 The z-norm check (||z||_inf < gamma1 - beta) at Algorithm 8 \
                                 line 13 may be missing or incorrect. gamma1={}, beta={}",
                                p.gamma1, p.beta
                            ),
                        };
                    }
                    // Rejected as expected.
                    TestOutcome::Pass
                } else {
                    TestOutcome::Error {
                        message: "ML_DSA_Verify missing 'valid' output".into(),
                    }
                }
            }
            Err(e) => harness_error_to_outcome(&e),
        }
    }
}

// ---------------------------------------------------------------------------
// Test 2: Malformed hint rejection
// ---------------------------------------------------------------------------

struct HintBitUnpackMalformedTest;

impl TestCase for HintBitUnpackMalformedTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("norms-malformed-hint-{parameter_set}"),
            name: "Verify rejects signatures with malformed hint encoding".to_string(),
            bug_class: BugClass::new("bounds-check", "hint-validation"),
            spec_ref: SpecReference::fips204("Algorithm 21 (HintBitUnpack), Algorithm 8 line 9"),
            severity: Severity::High,
            provenance: None,
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        let p = match params::params_by_name(parameter_set) {
            Some(p) => p,
            None => return TestOutcome::Error {
                message: format!("unknown parameter set: {parameter_set}"),
            },
        };

        let msg = b"malformed hint test";

        // Generate a valid signature to use as a template.
        let (pk, _sk, sig) = match generate_valid_tuple(harness, p, 0x22, msg) {
            Ok(t) => t,
            Err(o) => return o,
        };

        // The hint is at the end of the signature: last (omega + k) bytes.
        let hint_len = p.omega + p.k;
        if sig.len() < hint_len {
            return TestOutcome::Error {
                message: "signature too short to contain hint".into(),
            };
        }

        let hint_start = sig.len() - hint_len;

        // Malformation 1: Non-increasing indices.
        // Set two indices in the first polynomial's hint range to be decreasing.
        {
            let mut bad_sig = sig.clone();
            // Set first polynomial to have 2 hint bits at indices 10, 5 (non-increasing).
            bad_sig[hint_start] = 10;
            bad_sig[hint_start + 1] = 5; // must be > 10, but we put 5
            bad_sig[hint_start + p.omega] = 2; // 2 hints in first polynomial
            // Clear the remaining offset counters so they equal 2.
            for i in 1..p.k {
                bad_sig[hint_start + p.omega + i] = 2;
            }
            // Zero out the unused hint index slots.
            for i in 2..p.omega {
                bad_sig[hint_start + i] = 0;
            }

            let result = harness.call_fn(
                "ML_DSA_Verify",
                &[("pk", &pk), ("message", msg), ("sigma", &bad_sig)],
                &[],
            );

            match result {
                Ok(outputs) => {
                    if let Some(valid) = outputs.get("valid") {
                        if valid.len() >= 1 && valid[0] == 0x01 {
                            return TestOutcome::Fail {
                                expected: "rejection (valid = 0x00)".into(),
                                actual: "verification succeeded (valid = 0x01)".into(),
                                detail: "ML_DSA_Verify accepted a signature with non-increasing \
                                         hint indices. HintBitUnpack (Algorithm 21) must reject \
                                         non-increasing index sequences."
                                    .into(),
                            };
                        }
                    }
                }
                Err(e) => return harness_error_to_outcome(&e),
            }
        }

        // Malformation 2: Excess hint weight (more than omega nonzero hints).
        {
            let mut bad_sig = sig.clone();
            // Fill all omega slots with unique ascending indices and set all
            // polynomials to claim some of the total weight.
            for i in 0..p.omega {
                bad_sig[hint_start + i] = (i % 256) as u8;
            }
            // Make the offset counters claim all omega hints are in the first polynomial,
            // and set leftover (normally zero) bytes to nonzero.
            bad_sig[hint_start + p.omega] = p.omega as u8;
            for i in 1..p.k {
                bad_sig[hint_start + p.omega + i] = p.omega as u8;
            }
            // Now we have exactly omega hints, but let's also make a "leftover" byte nonzero.
            // Actually, since all omega slots are used, leftover check is satisfied.
            // Instead, let's set the first polynomial offset to more than omega.
            if p.omega < 255 {
                bad_sig[hint_start + p.omega] = (p.omega + 1) as u8;
            }

            let result = harness.call_fn(
                "ML_DSA_Verify",
                &[("pk", &pk), ("message", msg), ("sigma", &bad_sig)],
                &[],
            );

            match result {
                Ok(outputs) => {
                    if let Some(valid) = outputs.get("valid") {
                        if valid.len() >= 1 && valid[0] == 0x01 {
                            return TestOutcome::Fail {
                                expected: "rejection (valid = 0x00)".into(),
                                actual: "verification succeeded (valid = 0x01)".into(),
                                detail: "ML_DSA_Verify accepted a signature with excess hint \
                                         weight (offset counter > omega). HintBitUnpack must \
                                         reject this."
                                    .into(),
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
// Test 3: Hint leftover non-zero bytes
// ---------------------------------------------------------------------------

struct HintLeftoverNonZeroTest;

impl TestCase for HintLeftoverNonZeroTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("norms-hint-leftover-nonzero-{parameter_set}"),
            name: "Verify rejects signatures with non-zero leftover bytes in hint encoding"
                .to_string(),
            bug_class: BugClass::new("bounds-check", "hint-validation"),
            spec_ref: SpecReference::fips204("Algorithm 21 (HintBitUnpack), lines 16-19"),
            severity: Severity::High,
            provenance: None,
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        let p = match params::params_by_name(parameter_set) {
            Some(p) => p,
            None => return TestOutcome::Error {
                message: format!("unknown parameter set: {parameter_set}"),
            },
        };

        let msg = b"hint leftover test";

        // Generate a valid signature to use as a template.
        let (pk, _sk, sig) = match generate_valid_tuple(harness, p, 0x33, msg) {
            Ok(t) => t,
            Err(o) => return o,
        };

        // The hint is at the end of the signature: last (omega + k) bytes.
        // Layout per Algorithm 20 (HintBitPack):
        //   - omega bytes of hint index data
        //   - k bytes of offset counters
        //
        // Algorithm 21 (HintBitUnpack) lines 16-19 require that any
        // hint index bytes between the last used index and the omega
        // boundary must be zero. A non-zero leftover byte indicates
        // a malformed encoding that must be rejected.
        let hint_len = p.omega + p.k;
        let hint_start = sig.len() - hint_len;

        // Strategy: construct a hint where no polynomials have any hints
        // (all offset counters = 0), but set a leftover index byte to nonzero.
        let mut bad_sig = sig.clone();

        // Zero out all offset counters (no hints for any polynomial).
        for i in 0..p.k {
            bad_sig[hint_start + p.omega + i] = 0;
        }
        // Zero out all hint index slots first.
        for i in 0..p.omega {
            bad_sig[hint_start + i] = 0;
        }
        // Now set one "leftover" index byte to nonzero. Since all offset
        // counters are 0, ALL omega index bytes are leftover and must be 0.
        bad_sig[hint_start] = 1;

        let result = harness.call_fn(
            "ML_DSA_Verify",
            &[("pk", &pk), ("message", msg), ("sigma", &bad_sig)],
            &[],
        );

        match result {
            Ok(outputs) => {
                if let Some(valid) = outputs.get("valid") {
                    if valid.len() >= 1 && valid[0] == 0x01 {
                        return TestOutcome::Fail {
                            expected: "rejection (valid = 0x00)".into(),
                            actual: "verification succeeded (valid = 0x01)".into(),
                            detail: "ML_DSA_Verify accepted a signature with non-zero leftover \
                                     bytes in the hint encoding. HintBitUnpack (Algorithm 21, \
                                     lines 16-19) must verify that all unused hint index bytes \
                                     are zero. This check prevents signature malleability via \
                                     the hint padding."
                                .into(),
                        };
                    }
                    TestOutcome::Pass
                } else {
                    TestOutcome::Error {
                        message: "ML_DSA_Verify missing 'valid' output".into(),
                    }
                }
            }
            // An error response is also acceptable for malformed hints.
            Err(crucible_core::harness::HarnessError::HarnessError(_)) => TestOutcome::Pass,
            Err(e) => harness_error_to_outcome(&e),
        }
    }
}

// ---------------------------------------------------------------------------
// Test 4: Basic sign/verify round-trip
// ---------------------------------------------------------------------------

struct SignVerifyRoundTripTest;

impl TestCase for SignVerifyRoundTripTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("norms-sign-verify-roundtrip-{parameter_set}"),
            name: "Sign then Verify round-trip succeeds".to_string(),
            bug_class: BugClass::new("spec-divergence", "round-trip"),
            spec_ref: SpecReference::fips204("Algorithms 6-8"),
            severity: Severity::Critical,
            provenance: None,
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        let p = match params::params_by_name(parameter_set) {
            Some(p) => p,
            None => return TestOutcome::Error {
                message: format!("unknown parameter set: {parameter_set}"),
            },
        };

        let ps = param_set_id(p);

        // Test with several different messages.
        let messages: &[&[u8]] = &[
            b"hello world",
            b"The quick brown fox jumps over the lazy dog",
            &[0u8; 100],
            &[0xFFu8; 1],
        ];

        for msg in messages {
            let seed = [0xAA; 32];
            let rnd = [0u8; 32];

            let kg = match harness.call_fn(
                "ML_DSA_KeyGen",
                &[("seed", &seed)],
                &[("param_set", ps)],
            ) {
                Ok(r) => r,
                Err(e) => return harness_error_to_outcome(&e),
            };

            let pk = match kg.get("pk") {
                Some(b) => b.clone(),
                None => return TestOutcome::Error {
                    message: "keygen missing pk".into(),
                },
            };
            let sk = match kg.get("sk") {
                Some(b) => b.clone(),
                None => return TestOutcome::Error {
                    message: "keygen missing sk".into(),
                },
            };

            let sign_result = match harness.call_fn(
                "ML_DSA_Sign",
                &[("sk", &sk), ("message", *msg), ("rnd", &rnd)],
                &[],
            ) {
                Ok(r) => r,
                Err(e) => return harness_error_to_outcome(&e),
            };

            let sig = match sign_result.get("signature") {
                Some(b) => b.clone(),
                None => return TestOutcome::Error {
                    message: "sign missing signature".into(),
                },
            };

            let verify_result = match harness.call_fn(
                "ML_DSA_Verify",
                &[("pk", &pk), ("message", *msg), ("sigma", &sig)],
                &[],
            ) {
                Ok(r) => r,
                Err(e) => return harness_error_to_outcome(&e),
            };

            match verify_result.get("valid") {
                Some(v) if v.len() >= 1 && v[0] == 0x01 => {
                    // Pass for this message.
                }
                Some(v) => {
                    return TestOutcome::Fail {
                        expected: "valid = 0x01 (verification succeeds)".into(),
                        actual: format!("valid = 0x{:02x}", v.first().copied().unwrap_or(0)),
                        detail: format!(
                            "Sign/Verify round-trip failed for {parameter_set} with a \
                             {}-byte message. A valid signature was rejected by Verify.",
                            msg.len()
                        ),
                    };
                }
                None => return TestOutcome::Error {
                    message: "ML_DSA_Verify missing 'valid' output".into(),
                },
            }
        }

        TestOutcome::Pass
    }
}
