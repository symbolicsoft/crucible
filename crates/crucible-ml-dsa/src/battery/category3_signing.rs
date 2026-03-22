//! Category 3: Signature Generation Internals.
//!
//! Tests for deterministic signing, deterministic keygen, and
//! SampleInBall properties. These verify that internal signing
//! algorithms produce correct outputs.

use crucible_core::harness::Harness;
use crucible_core::orchestrator::{harness_error_to_outcome, TestCase, TestCategory};
use crucible_core::verdict::*;
use crate::params::{self, MlDsaParams};

pub fn category() -> TestCategory {
    TestCategory {
        name: "signing".to_string(),
        tests: vec![
            Box::new(DeterministicSignTest),
            Box::new(DeterministicKeygenTest),
            Box::new(SampleInBallPropertiesTest),
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
// Test 1: Deterministic signing matches reference
// ---------------------------------------------------------------------------

struct DeterministicSignTest;

impl TestCase for DeterministicSignTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("signing-deterministic-sign-{parameter_set}"),
            name: "Deterministic signing (rnd=0^32) matches reference byte-for-byte".to_string(),
            bug_class: BugClass::new("spec-divergence", "signing"),
            spec_ref: SpecReference::fips204("Algorithm 7 (ML-DSA.Sign_internal)"),
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
        let seed = [0x42u8; 32];
        let rnd = [0u8; 32]; // deterministic: rnd = 0^32
        let msg = b"deterministic signing test";

        // Generate keys via harness.
        let kg = match harness.call_fn(
            "ML_DSA_KeyGen",
            &[("seed", &seed)],
            &[("param_set", ps)],
        ) {
            Ok(r) => r,
            Err(e) => return harness_error_to_outcome(&e),
        };

        let harness_sk = match kg.get("sk") {
            Some(b) => b.clone(),
            None => return TestOutcome::Error {
                message: "keygen missing sk".into(),
            },
        };

        // Sign via harness.
        let sign_result = match harness.call_fn(
            "ML_DSA_Sign",
            &[("sk", &harness_sk), ("message", msg.as_slice()), ("rnd", &rnd)],
            &[],
        ) {
            Ok(r) => r,
            Err(e) => return harness_error_to_outcome(&e),
        };

        let harness_sig = match sign_result.get("signature") {
            Some(b) => b.clone(),
            None => return TestOutcome::Error {
                message: "sign missing signature".into(),
            },
        };

        // Compute reference signature using our implementation with the same sk.
        let ref_sig = match crate::math::sign::sign_internal(&harness_sk, msg, &rnd, p) {
            Some(s) => s.sigma,
            None => return TestOutcome::Error {
                message: "reference sign_internal failed (exceeded max iterations)".into(),
            },
        };

        if harness_sig != ref_sig {
            let diff_pos = harness_sig
                .iter()
                .zip(ref_sig.iter())
                .position(|(a, b)| a != b)
                .unwrap_or(harness_sig.len().min(ref_sig.len()));
            return TestOutcome::Fail {
                expected: format!(
                    "sig[{diff_pos}] = 0x{:02x}",
                    ref_sig.get(diff_pos).copied().unwrap_or(0)
                ),
                actual: format!(
                    "sig[{diff_pos}] = 0x{:02x}",
                    harness_sig.get(diff_pos).copied().unwrap_or(0)
                ),
                detail: format!(
                    "Deterministic signing ({parameter_set}, rnd=0^32) produced different \
                     signature at byte {diff_pos}. This indicates a divergence in Sign_internal \
                     (Algorithm 7): ExpandMask, challenge generation, z/hint computation, or \
                     encoding. sig lengths: got {}, expected {}.",
                    harness_sig.len(),
                    ref_sig.len()
                ),
            };
        }

        TestOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// Test 2: Deterministic keygen matches reference
// ---------------------------------------------------------------------------

struct DeterministicKeygenTest;

impl TestCase for DeterministicKeygenTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("signing-deterministic-keygen-{parameter_set}"),
            name: "Deterministic keygen matches reference byte-for-byte".to_string(),
            bug_class: BugClass::new("spec-divergence", "keygen"),
            spec_ref: SpecReference::fips204("Algorithm 6 (ML-DSA.KeyGen_internal)"),
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

        // Test with multiple seeds.
        for &seed_val in &[0x00u8, 0x42, 0xAB, 0xFF] {
            let seed = [seed_val; 32];

            let kg = match harness.call_fn(
                "ML_DSA_KeyGen",
                &[("seed", &seed)],
                &[("param_set", ps)],
            ) {
                Ok(r) => r,
                Err(e) => return harness_error_to_outcome(&e),
            };

            let harness_pk = match kg.get("pk") {
                Some(b) => b.clone(),
                None => return TestOutcome::Error {
                    message: "keygen missing pk".into(),
                },
            };
            let harness_sk = match kg.get("sk") {
                Some(b) => b.clone(),
                None => return TestOutcome::Error {
                    message: "keygen missing sk".into(),
                },
            };

            let ref_kp = crate::math::sign::keygen_internal(&seed, p);

            if harness_pk != ref_kp.pk {
                let diff_pos = harness_pk
                    .iter()
                    .zip(ref_kp.pk.iter())
                    .position(|(a, b)| a != b)
                    .unwrap_or(0);
                return TestOutcome::Fail {
                    expected: format!(
                        "pk[{diff_pos}] = 0x{:02x}",
                        ref_kp.pk.get(diff_pos).copied().unwrap_or(0)
                    ),
                    actual: format!(
                        "pk[{diff_pos}] = 0x{:02x}",
                        harness_pk.get(diff_pos).copied().unwrap_or(0)
                    ),
                    detail: format!(
                        "Deterministic keygen ({parameter_set}, seed=0x{seed_val:02x}) \
                         produced different pk at byte {diff_pos}. \
                         pk lengths: got {}, expected {}.",
                        harness_pk.len(),
                        ref_kp.pk.len()
                    ),
                };
            }

            if harness_sk != ref_kp.sk {
                let diff_pos = harness_sk
                    .iter()
                    .zip(ref_kp.sk.iter())
                    .position(|(a, b)| a != b)
                    .unwrap_or(0);
                return TestOutcome::Fail {
                    expected: format!(
                        "sk[{diff_pos}] = 0x{:02x}",
                        ref_kp.sk.get(diff_pos).copied().unwrap_or(0)
                    ),
                    actual: format!(
                        "sk[{diff_pos}] = 0x{:02x}",
                        harness_sk.get(diff_pos).copied().unwrap_or(0)
                    ),
                    detail: format!(
                        "Deterministic keygen ({parameter_set}, seed=0x{seed_val:02x}) \
                         produced different sk at byte {diff_pos}. \
                         sk lengths: got {}, expected {}.",
                        harness_sk.len(),
                        ref_kp.sk.len()
                    ),
                };
            }
        }

        TestOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// Test 3: SampleInBall properties
// ---------------------------------------------------------------------------

struct SampleInBallPropertiesTest;

impl TestCase for SampleInBallPropertiesTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("signing-sample-in-ball-{parameter_set}"),
            name: "SampleInBall produces exactly tau nonzero coefficients, all +/-1".to_string(),
            bug_class: BugClass::new("spec-divergence", "sampling"),
            spec_ref: SpecReference::fips204("Algorithm 29 (SampleInBall)"),
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

        // SampleInBall is an internal function that most implementations will not
        // expose directly. We test it indirectly: if SampleInBall is wrong, then
        // the challenge polynomial c will have wrong properties, and verification
        // will fail for a valid signature or succeed for an invalid one.
        //
        // We verify our reference SampleInBall properties, then check that
        // sign/verify works (which exercises SampleInBall in both signer and verifier).
        let ps = param_set_id(p);

        // Verify reference SampleInBall with multiple inputs.
        for seed_val in [0x00u8, 0x42, 0xAB, 0xFF] {
            let rho = vec![seed_val; p.lambda / 4];
            let c = crate::math::sampling::sample_in_ball(&rho, p.tau);

            // Property 1: exactly tau nonzero coefficients.
            let nonzero_count = c.iter().filter(|&&x| x != 0).count();
            if nonzero_count != p.tau {
                return TestOutcome::Fail {
                    expected: format!("{} nonzero coefficients", p.tau),
                    actual: format!("{nonzero_count} nonzero coefficients"),
                    detail: format!(
                        "SampleInBall (seed=0x{seed_val:02x}, tau={}) produced {nonzero_count} \
                         nonzero coefficients instead of {}.",
                        p.tau, p.tau
                    ),
                };
            }

            // Property 2: all nonzero coefficients are +1 or -1.
            for (i, &coeff) in c.iter().enumerate() {
                if coeff != 0 && coeff != 1 && coeff != -1 {
                    return TestOutcome::Fail {
                        expected: "all nonzero coefficients in {-1, +1}".into(),
                        actual: format!("c[{i}] = {coeff}"),
                        detail: format!(
                            "SampleInBall (seed=0x{seed_val:02x}) produced coefficient \
                             c[{i}] = {coeff}, which is not in {{-1, 0, +1}}."
                        ),
                    };
                }
            }
        }

        // Black-box test: sign/verify exercises SampleInBall on both sides.
        let seed = [0x77u8; 32];
        let rnd = [0u8; 32];
        let msg = b"sample_in_ball properties test";

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
            &[("sk", &sk), ("message", msg.as_slice()), ("rnd", &rnd)],
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

        // Cross-verify: verify with our reference implementation.
        if !crate::math::sign::verify_internal(&pk, msg, &sig, p) {
            return TestOutcome::Fail {
                expected: "reference verify succeeds".into(),
                actual: "reference verify failed".into(),
                detail: format!(
                    "Signature from harness fails reference verification for {parameter_set}. \
                     This may indicate a SampleInBall divergence: the challenge polynomial \
                     c must be identical in signer and verifier."
                ),
            };
        }

        TestOutcome::Pass
    }
}
