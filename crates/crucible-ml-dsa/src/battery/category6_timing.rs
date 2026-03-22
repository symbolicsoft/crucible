//! Category 6: Constant-Time Behavior.
//!
//! Tests for deterministic vs hedged signing behavior. These are not
//! true timing side-channel tests (which require hardware-level
//! measurement), but verify the observable contract: deterministic
//! mode produces the same output, hedged mode produces different outputs.

use crucible_core::harness::Harness;
use crucible_core::orchestrator::{harness_error_to_outcome, TestCase, TestCategory};
use crucible_core::verdict::*;
use crate::params::{self, MlDsaParams};

pub fn category() -> TestCategory {
    TestCategory {
        name: "timing".to_string(),
        tests: vec![
            Box::new(SigningDeterminismTest),
            Box::new(HedgedSigningVarianceTest),
        ],
    }
}

/// Extract the numeric suffix from a parameter set name for the harness param.
fn param_set_id(p: &MlDsaParams) -> i64 {
    match p.name {
        "ML-DSA-44" => 44,
        "ML-DSA-65" => 65,
        "ML-DSA-87" => 87,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Test 1: Deterministic signing produces same output
// ---------------------------------------------------------------------------

struct SigningDeterminismTest;

impl TestCase for SigningDeterminismTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("timing-signing-determinism-{parameter_set}"),
            name: "Deterministic signing (rnd=0^32) produces identical output".to_string(),
            bug_class: BugClass::new("spec-divergence", "determinism"),
            spec_ref: SpecReference::fips204("Algorithm 7, line 7 (rho'' computation)"),
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

        let ps = param_set_id(p);
        let seed = [0x42u8; 32];
        let rnd = [0u8; 32]; // deterministic mode
        let msg = b"determinism test message";

        // Generate keys.
        let kg = match harness.call_fn(
            "ML_DSA_KeyGen",
            &[("seed", &seed)],
            &[("param_set", ps)],
        ) {
            Ok(r) => r,
            Err(e) => return harness_error_to_outcome(&e),
        };

        let sk = match kg.get("sk") {
            Some(b) => b.clone(),
            None => return TestOutcome::Error {
                message: "keygen missing sk".into(),
            },
        };

        // Sign twice with the same inputs.
        let sign1 = match harness.call_fn(
            "ML_DSA_Sign",
            &[("sk", &sk), ("message", msg.as_slice()), ("rnd", &rnd)],
            &[],
        ) {
            Ok(r) => r,
            Err(e) => return harness_error_to_outcome(&e),
        };

        let sig1 = match sign1.get("signature") {
            Some(b) => b.clone(),
            None => return TestOutcome::Error {
                message: "first sign missing signature".into(),
            },
        };

        let sign2 = match harness.call_fn(
            "ML_DSA_Sign",
            &[("sk", &sk), ("message", msg.as_slice()), ("rnd", &rnd)],
            &[],
        ) {
            Ok(r) => r,
            Err(e) => return harness_error_to_outcome(&e),
        };

        let sig2 = match sign2.get("signature") {
            Some(b) => b.clone(),
            None => return TestOutcome::Error {
                message: "second sign missing signature".into(),
            },
        };

        if sig1 != sig2 {
            let diff_pos = sig1
                .iter()
                .zip(sig2.iter())
                .position(|(a, b)| a != b)
                .unwrap_or(sig1.len().min(sig2.len()));
            return TestOutcome::Fail {
                expected: "identical signatures for same (sk, msg, rnd=0^32)".into(),
                actual: format!(
                    "signatures differ at byte {diff_pos} (0x{:02x} vs 0x{:02x})",
                    sig1.get(diff_pos).copied().unwrap_or(0),
                    sig2.get(diff_pos).copied().unwrap_or(0)
                ),
                detail: format!(
                    "Two calls to ML_DSA_Sign with identical inputs (sk, message, rnd=0^32) \
                     produced different signatures for {parameter_set}. In deterministic mode \
                     (rnd = 0^32), the signing algorithm must be fully deterministic because \
                     rho'' = H(K || rnd || mu) is fixed."
                ),
            };
        }

        // Also test with a different message to confirm the signatures differ.
        let msg2 = b"different message for determinism";
        let sign3 = match harness.call_fn(
            "ML_DSA_Sign",
            &[("sk", &sk), ("message", msg2.as_slice()), ("rnd", &rnd)],
            &[],
        ) {
            Ok(r) => r,
            Err(e) => return harness_error_to_outcome(&e),
        };

        let sig3 = match sign3.get("signature") {
            Some(b) => b.clone(),
            None => return TestOutcome::Error {
                message: "third sign missing signature".into(),
            },
        };

        if sig1 == sig3 {
            return TestOutcome::Fail {
                expected: "different signatures for different messages".into(),
                actual: "identical signatures for different messages".into(),
                detail: format!(
                    "ML_DSA_Sign produced the same signature for two different messages \
                     on {parameter_set}. The message is hashed into mu, which feeds into \
                     the signing algorithm. Identical output for different messages \
                     indicates the message is not being incorporated."
                ),
            };
        }

        TestOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// Test 2: Hedged signing variance
// ---------------------------------------------------------------------------

struct HedgedSigningVarianceTest;

impl TestCase for HedgedSigningVarianceTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("timing-hedged-signing-variance-{parameter_set}"),
            name: "Hedged signing (different rnd) produces different signatures".to_string(),
            bug_class: BugClass::new("spec-divergence", "hedging"),
            spec_ref: SpecReference::fips204("Algorithm 7, line 7 (rho'' = H(K || rnd || mu))"),
            severity: Severity::Medium,
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
        let seed = [0x42u8; 32];
        let msg = b"hedged signing test message";

        // Generate keys.
        let kg = match harness.call_fn(
            "ML_DSA_KeyGen",
            &[("seed", &seed)],
            &[("param_set", ps)],
        ) {
            Ok(r) => r,
            Err(e) => return harness_error_to_outcome(&e),
        };

        let sk = match kg.get("sk") {
            Some(b) => b.clone(),
            None => return TestOutcome::Error {
                message: "keygen missing sk".into(),
            },
        };
        let pk = match kg.get("pk") {
            Some(b) => b.clone(),
            None => return TestOutcome::Error {
                message: "keygen missing pk".into(),
            },
        };

        // Sign with two different rnd values (non-zero = hedged mode).
        let rnd1 = [0x01u8; 32];
        let rnd2 = [0x02u8; 32];

        let sign1 = match harness.call_fn(
            "ML_DSA_Sign",
            &[("sk", &sk), ("message", msg.as_slice()), ("rnd", &rnd1)],
            &[],
        ) {
            Ok(r) => r,
            Err(e) => return harness_error_to_outcome(&e),
        };

        let sig1 = match sign1.get("signature") {
            Some(b) => b.clone(),
            None => return TestOutcome::Error {
                message: "first hedged sign missing signature".into(),
            },
        };

        let sign2 = match harness.call_fn(
            "ML_DSA_Sign",
            &[("sk", &sk), ("message", msg.as_slice()), ("rnd", &rnd2)],
            &[],
        ) {
            Ok(r) => r,
            Err(e) => return harness_error_to_outcome(&e),
        };

        let sig2 = match sign2.get("signature") {
            Some(b) => b.clone(),
            None => return TestOutcome::Error {
                message: "second hedged sign missing signature".into(),
            },
        };

        // With different rnd values, the signatures should almost certainly differ
        // because rho'' = H(K || rnd || mu) will differ, leading to different
        // masking vectors y and thus different z/hint values.
        if sig1 == sig2 {
            return TestOutcome::Fail {
                expected: "different signatures for different rnd values".into(),
                actual: "identical signatures despite different rnd".into(),
                detail: format!(
                    "ML_DSA_Sign produced identical signatures with rnd=0x01^32 and \
                     rnd=0x02^32 for {parameter_set}. The rnd value feeds into \
                     rho'' = H(K || rnd || mu), so different rnd should produce \
                     different masking vectors and thus different signatures. \
                     The implementation may be ignoring the rnd parameter."
                ),
            };
        }

        // Both signatures must still be valid.
        for (i, sig) in [&sig1, &sig2].iter().enumerate() {
            let result = match harness.call_fn(
                "ML_DSA_Verify",
                &[("pk", &pk), ("message", msg.as_slice()), ("sigma", sig)],
                &[],
            ) {
                Ok(r) => r,
                Err(e) => return harness_error_to_outcome(&e),
            };

            match result.get("valid") {
                Some(v) if v.len() >= 1 && v[0] == 0x01 => {}
                Some(v) => {
                    return TestOutcome::Fail {
                        expected: "valid = 0x01".into(),
                        actual: format!("valid = 0x{:02x}", v.first().copied().unwrap_or(0)),
                        detail: format!(
                            "Hedged signature {} failed verification for {parameter_set}. \
                             Different rnd values should produce different but still valid \
                             signatures.",
                            i + 1
                        ),
                    };
                }
                None => return TestOutcome::Error {
                    message: format!("ML_DSA_Verify missing 'valid' output for hedged sig {}", i + 1),
                },
            }
        }

        TestOutcome::Pass
    }
}
