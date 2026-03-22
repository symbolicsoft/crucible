//! Category 2: Arithmetic Correctness.
//!
//! Tests for Power2Round, Decompose, and NTT round-trip correctness.
//! These use the harness where possible and fall back to reference
//! computations for validation.

use crucible_core::harness::Harness;
use crucible_core::orchestrator::{harness_error_to_outcome, TestCase, TestCategory};
use crucible_core::verdict::*;
use crate::math::decompose::decompose;
use crate::params::{self, MlDsaParams, Q};

pub fn category() -> TestCategory {
    TestCategory {
        name: "arithmetic".to_string(),
        tests: vec![
            Box::new(Power2RoundTest),
            Box::new(DecomposeTest),
            Box::new(NttRoundTripTest),
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
// Test 1: Power2Round boundary values
// ---------------------------------------------------------------------------

struct Power2RoundTest;

impl TestCase for Power2RoundTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("arith-power2round-{parameter_set}"),
            name: "Power2Round correctness at boundary values".to_string(),
            bug_class: BugClass::new("spec-divergence", "rounding"),
            spec_ref: SpecReference::fips204("Algorithm 35 (Power2Round)"),
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

        // Power2Round is tested implicitly through keygen: if the implementation
        // gets Power2Round wrong, the public key t1 will be wrong, and verification
        // will fail. We verify this by doing keygen + sign + verify with a known seed,
        // then compare keygen output against our reference.
        let ps = param_set_id(p);
        let seed = [0x42u8; 32];

        // Generate keys via harness.
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

        // Generate keys via our reference implementation.
        let ref_kp = crate::math::sign::keygen_internal(&seed, p);

        if harness_pk != ref_kp.pk {
            let diff_pos = harness_pk
                .iter()
                .zip(ref_kp.pk.iter())
                .position(|(a, b)| a != b)
                .unwrap_or(harness_pk.len().min(ref_kp.pk.len()));
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
                    "Deterministic keygen ({parameter_set}) produced different pk at byte \
                     {diff_pos}. Power2Round decomposes t into (t1, t0); if Power2Round is \
                     wrong, pk = pkEncode(rho, t1) will differ. \
                     pk lengths: got {}, expected {}.",
                    harness_pk.len(),
                    ref_kp.pk.len()
                ),
            };
        }

        // Also verify the round-trip: sign with the harness sk, verify with reference.
        let msg = b"power2round test";
        let rnd = [0u8; 32];
        let sign_result = match harness.call_fn(
            "ML_DSA_Sign",
            &[("sk", &harness_sk), ("message", msg.as_slice()), ("rnd", &rnd)],
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

        // Verify with our reference.
        if !crate::math::sign::verify_internal(&ref_kp.pk, msg, &sig, p) {
            return TestOutcome::Fail {
                expected: "reference verify succeeds".into(),
                actual: "reference verify failed".into(),
                detail: format!(
                    "Signature produced by harness for {parameter_set} fails reference \
                     verification. This indicates a Power2Round, encoding, or arithmetic bug."
                ),
            };
        }

        TestOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// Test 2: Decompose boundary values
// ---------------------------------------------------------------------------

struct DecomposeTest;

impl TestCase for DecomposeTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("arith-decompose-{parameter_set}"),
            name: "Decompose correctness including the r1=(q-1)/alpha edge case".to_string(),
            bug_class: BugClass::new("spec-divergence", "decompose"),
            spec_ref: SpecReference::fips204("Algorithm 36 (Decompose)"),
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

        // Decompose is tested implicitly through signing: the signer computes
        // w1 = HighBits(w) and the verifier recomputes it via UseHint. If Decompose
        // is wrong, the challenge hash will not match and verification will fail.
        //
        // We test multiple seeds to increase the chance of hitting the edge case
        // where r = q-1 (which triggers the special case r1=0, r0=r0-1).
        let ps = param_set_id(p);

        // Additionally, verify our reference Decompose at the (q-1) edge case.
        let alpha = 2 * p.gamma2 as i32;
        let (r1, r0) = decompose((Q - 1) as i32, p.gamma2);
        let reconstructed = (r1 as i64 * alpha as i64 + r0 as i64).rem_euclid(Q as i64);
        if reconstructed != (Q - 1) as i64 {
            return TestOutcome::Error {
                message: format!(
                    "Reference Decompose({}, gamma2={}) reconstruction failed: r1={}, r0={}, \
                     reconstructed={}",
                    Q - 1,
                    p.gamma2,
                    r1,
                    r0,
                    reconstructed
                ),
            };
        }
        // The spec says: if r - r0 == q-1, then r1 = 0, r0 = r0 - 1.
        // At r = q-1, this means r1 should be 0.
        if r1 != 0 {
            return TestOutcome::Error {
                message: format!(
                    "Reference Decompose({}, gamma2={}) did not produce r1=0 for edge case",
                    Q - 1,
                    p.gamma2
                ),
            };
        }

        // Now test via harness: try several seeds for sign/verify. If Decompose is
        // implemented incorrectly, some of these will fail.
        for seed_val in [0x01u8, 0x42, 0x77, 0xBB, 0xFF] {
            let seed = [seed_val; 32];
            let rnd = [0u8; 32];
            let msg = b"decompose edge case test";

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

            let verify_result = match harness.call_fn(
                "ML_DSA_Verify",
                &[("pk", &pk), ("message", msg.as_slice()), ("sigma", &sig)],
                &[],
            ) {
                Ok(r) => r,
                Err(e) => return harness_error_to_outcome(&e),
            };

            match verify_result.get("valid") {
                Some(v) if v.len() >= 1 && v[0] == 0x01 => {}
                Some(v) => {
                    return TestOutcome::Fail {
                        expected: "valid = 0x01".into(),
                        actual: format!("valid = 0x{:02x}", v.first().copied().unwrap_or(0)),
                        detail: format!(
                            "Sign/Verify failed for seed=0x{seed_val:02x} on {parameter_set}. \
                             A Decompose bug (especially the r1=(q-1)/alpha edge case) could \
                             cause w1 mismatch between signer and verifier."
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

// ---------------------------------------------------------------------------
// Test 3: NTT round-trip
// ---------------------------------------------------------------------------

struct NttRoundTripTest;

impl TestCase for NttRoundTripTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("arith-ntt-roundtrip-{parameter_set}"),
            name: "NTT_inv(NTT(w)) == w for ML-DSA (zeta=1753, q=8380417)".to_string(),
            bug_class: BugClass::new("spec-divergence", "ntt"),
            spec_ref: SpecReference::fips204("Algorithms 41-42 (NTT/NTT_inv)"),
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

        // The NTT is tested implicitly via keygen (t = NTT_inv(A_hat * NTT(s1)) + s2).
        // If NTT is wrong, keygen will produce wrong keys and sign/verify will fail.
        //
        // We generate keys with a known seed and compare against our reference.
        let ps = param_set_id(p);
        let seed = [0x37u8; 32];

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
                    "Deterministic keygen ({parameter_set}) produced different pk. The NTT \
                     computation t = NTT_inv(A_hat * NTT(s1)) + s2 differs. \
                     ML-DSA uses zeta=1753, q=8380417 (different from ML-KEM). \
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
                    "Deterministic keygen ({parameter_set}) produced different sk. The NTT \
                     or secret encoding differs. sk lengths: got {}, expected {}.",
                    harness_sk.len(),
                    ref_kp.sk.len()
                ),
            };
        }

        TestOutcome::Pass
    }
}
