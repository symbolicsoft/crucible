//! Category 5: Serialization and Key Validation.
//!
//! Tests for key encoding round-trips, and rejection of wrong-length
//! signatures and public keys.

use crucible_core::harness::Harness;
use crucible_core::orchestrator::{harness_error_to_outcome, TestCase, TestCategory};
use crucible_core::verdict::*;
use crate::params::{self, MlDsaParams, expected_pk_len, expected_sk_len, expected_sig_len};

pub fn category() -> TestCategory {
    TestCategory {
        name: "serialization".to_string(),
        tests: vec![
            Box::new(KeyEncodingRoundTripTest),
            Box::new(SignatureLengthTest),
            Box::new(PublicKeyLengthTest),
            Box::new(SecretKeyLengthTest),
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
// Test 1: Key encoding round-trip
// ---------------------------------------------------------------------------

struct KeyEncodingRoundTripTest;

impl TestCase for KeyEncodingRoundTripTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("serial-key-encoding-roundtrip-{parameter_set}"),
            name: "Key encoding round-trip: keygen then sign/verify works".to_string(),
            bug_class: BugClass::new("spec-divergence", "encoding-round-trip"),
            spec_ref: SpecReference::fips204("Algorithms 22-25 (pkEncode/skEncode/pkDecode/skDecode)"),
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

        // Generate fresh keys and verify that sign/verify works with them.
        // This implicitly tests pkEncode, skEncode, pkDecode, skDecode.
        for &seed_val in &[0x01u8, 0xCC, 0xFF] {
            let seed = [seed_val; 32];
            let rnd = [0u8; 32];
            let msg = b"key encoding round-trip test";

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

            // Verify key sizes.
            let exp_pk = expected_pk_len(p);
            let exp_sk = expected_sk_len(p);
            if pk.len() != exp_pk {
                return TestOutcome::Fail {
                    expected: format!("{exp_pk} bytes"),
                    actual: format!("{} bytes", pk.len()),
                    detail: format!(
                        "Public key length for {parameter_set} (seed=0x{seed_val:02x}) \
                         is {} bytes, expected {exp_pk}.",
                        pk.len()
                    ),
                };
            }
            if sk.len() != exp_sk {
                return TestOutcome::Fail {
                    expected: format!("{exp_sk} bytes"),
                    actual: format!("{} bytes", sk.len()),
                    detail: format!(
                        "Secret key length for {parameter_set} (seed=0x{seed_val:02x}) \
                         is {} bytes, expected {exp_sk}.",
                        sk.len()
                    ),
                };
            }

            // Sign and verify to test that the encoded keys work correctly.
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

            // Verify signature size.
            let exp_sig = expected_sig_len(p);
            if sig.len() != exp_sig {
                return TestOutcome::Fail {
                    expected: format!("{exp_sig} bytes"),
                    actual: format!("{} bytes", sig.len()),
                    detail: format!(
                        "Signature length for {parameter_set} is {} bytes, expected {exp_sig}.",
                        sig.len()
                    ),
                };
            }

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
                            "Sign/Verify failed with freshly generated keys for \
                             {parameter_set} (seed=0x{seed_val:02x}). This indicates an \
                             encoding round-trip bug in pkEncode/skEncode/pkDecode/skDecode."
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
// Test 2: Wrong-length signatures rejected
// ---------------------------------------------------------------------------

struct SignatureLengthTest;

impl TestCase for SignatureLengthTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("serial-sig-length-{parameter_set}"),
            name: "Wrong-length signatures are rejected by Verify".to_string(),
            bug_class: BugClass::new("bounds-check", "signature-length"),
            spec_ref: SpecReference::fips204("Algorithm 8, signature parsing"),
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
        let seed = [0x33u8; 32];
        let msg = b"sig length test";

        // Generate a valid keypair for verification.
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

        let exp_sig = expected_sig_len(p);

        // Test wrong-length signatures.
        let bad_lengths: Vec<usize> = vec![
            0,
            1,
            exp_sig - 1,
            exp_sig + 1,
            exp_sig / 2,
            exp_sig * 2,
        ];

        for bad_len in bad_lengths {
            let bad_sig = vec![0u8; bad_len];

            let result = harness.call_fn(
                "ML_DSA_Verify",
                &[("pk", &pk), ("message", msg.as_slice()), ("sigma", &bad_sig)],
                &[],
            );

            match result {
                Ok(outputs) => {
                    if let Some(valid) = outputs.get("valid") {
                        if valid.len() >= 1 && valid[0] == 0x01 {
                            return TestOutcome::Fail {
                                expected: format!(
                                    "rejection for {bad_len}-byte signature (expected {exp_sig})"
                                ),
                                actual: "verification succeeded".into(),
                                detail: format!(
                                    "ML_DSA_Verify accepted a {bad_len}-byte signature for \
                                     {parameter_set} (expected {exp_sig} bytes). The verifier \
                                     must reject signatures of incorrect length."
                                ),
                            };
                        }
                        // Rejected as expected (valid = 0x00).
                    }
                }
                // An error is also acceptable: some implementations may error
                // rather than returning valid=false for malformed inputs.
                Err(crucible_core::harness::HarnessError::HarnessError(_)) => {}
                Err(e) => return harness_error_to_outcome(&e),
            }
        }

        TestOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// Test 3: Wrong-length public keys rejected
// ---------------------------------------------------------------------------

struct PublicKeyLengthTest;

impl TestCase for PublicKeyLengthTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("serial-pk-length-{parameter_set}"),
            name: "Wrong-length public keys are rejected by Verify".to_string(),
            bug_class: BugClass::new("bounds-check", "pk-length"),
            spec_ref: SpecReference::fips204("Algorithm 8, public key parsing"),
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
        let seed = [0x44u8; 32];
        let msg = b"pk length test";
        let rnd = [0u8; 32];

        // Generate a valid keypair and signature.
        let kg = match harness.call_fn(
            "ML_DSA_KeyGen",
            &[("seed", &seed)],
            &[("param_set", ps)],
        ) {
            Ok(r) => r,
            Err(e) => return harness_error_to_outcome(&e),
        };

        let _pk = match kg.get("pk") {
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

        let exp_pk = expected_pk_len(p);

        // Test wrong-length public keys.
        let bad_lengths: Vec<usize> = vec![
            0,
            1,
            exp_pk - 1,
            exp_pk + 1,
            exp_pk / 2,
        ];

        for bad_len in bad_lengths {
            let bad_pk = vec![0u8; bad_len];

            let result = harness.call_fn(
                "ML_DSA_Verify",
                &[("pk", &bad_pk), ("message", msg.as_slice()), ("sigma", &sig)],
                &[],
            );

            match result {
                Ok(outputs) => {
                    if let Some(valid) = outputs.get("valid") {
                        if valid.len() >= 1 && valid[0] == 0x01 {
                            return TestOutcome::Fail {
                                expected: format!(
                                    "rejection for {bad_len}-byte pk (expected {exp_pk})"
                                ),
                                actual: "verification succeeded".into(),
                                detail: format!(
                                    "ML_DSA_Verify accepted a {bad_len}-byte public key for \
                                     {parameter_set} (expected {exp_pk} bytes). The verifier \
                                     must reject public keys of incorrect length."
                                ),
                            };
                        }
                        // Rejected as expected.
                    }
                }
                // An error is also acceptable for malformed inputs.
                Err(crucible_core::harness::HarnessError::HarnessError(_)) => {}
                Err(e) => return harness_error_to_outcome(&e),
            }
        }

        TestOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// Test 4: Wrong-length secret keys rejected by Sign
// ---------------------------------------------------------------------------

struct SecretKeyLengthTest;

impl TestCase for SecretKeyLengthTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("serial-sk-length-{parameter_set}"),
            name: "Wrong-length secret keys are rejected by Sign".to_string(),
            bug_class: BugClass::new("bounds-check", "sk-length"),
            spec_ref: SpecReference::fips204("Algorithm 7, sk parsing via skDecode"),
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

        let msg = b"sk length test";
        let rnd = [0u8; 32];
        let exp_sk = expected_sk_len(p);

        // Test wrong-length secret keys.
        let bad_lengths: Vec<usize> = vec![
            0,
            1,
            exp_sk - 1,
            exp_sk + 1,
            exp_sk / 2,
        ];

        for bad_len in bad_lengths {
            let bad_sk = vec![0u8; bad_len];

            let result = harness.call_fn(
                "ML_DSA_Sign",
                &[("sk", &bad_sk), ("message", msg.as_slice()), ("rnd", &rnd)],
                &[],
            );

            match result {
                Ok(outputs) => {
                    // If the harness returned a signature, check that it's at least
                    // not the expected length (indicating it was confused about params).
                    if let Some(sig) = outputs.get("signature") {
                        let exp_sig = expected_sig_len(p);
                        if sig.len() == exp_sig {
                            // A valid-looking signature from a wrong-length sk is a problem.
                            return TestOutcome::Fail {
                                expected: format!(
                                    "error or rejection for {bad_len}-byte sk (expected {exp_sk})"
                                ),
                                actual: format!("produced {}-byte signature", sig.len()),
                                detail: format!(
                                    "ML_DSA_Sign accepted a {bad_len}-byte secret key for \
                                     {parameter_set} (expected {exp_sk} bytes) and produced a \
                                     valid-looking signature. The signer must validate sk length \
                                     to prevent buffer over-reads during skDecode."
                                ),
                            };
                        }
                    }
                    // No signature or wrong-sized signature: acceptable behavior.
                }
                // An error is the expected behavior for malformed sk.
                Err(crucible_core::harness::HarnessError::HarnessError(_)) => {}
                Err(e) => return harness_error_to_outcome(&e),
            }
        }

        TestOutcome::Pass
    }
}
