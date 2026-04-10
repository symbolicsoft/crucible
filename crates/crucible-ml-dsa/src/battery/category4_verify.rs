//! Category 4: Verification Edge Cases.
//!
//! Tests that verification correctly rejects corrupted signatures,
//! signatures under wrong keys, and handles empty messages.

use crucible_core::harness::Harness;
use crucible_core::orchestrator::{harness_error_to_outcome, TestCase, TestCategory};
use crucible_core::verdict::*;
use crate::params::{self, MlDsaParams, expected_pk_len, expected_sk_len, expected_sig_len};

pub fn category() -> TestCategory {
    TestCategory {
        name: "verification".to_string(),
        tests: vec![
            Box::new(SignatureMalleabilityTest),
            Box::new(WrongKeyRejectionTest),
            Box::new(EmptyMessageTest),
            Box::new(MessageIntegrityTest),
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

/// Helper: generate a keypair and signature via the harness.
fn generate_keypair_and_sig(
    harness: &mut Harness,
    p: &MlDsaParams,
    seed: &[u8; 32],
    msg: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), TestOutcome> {
    let ps = param_set_id(p);
    let rnd = [0u8; 32];

    let kg = harness
        .call_fn("ML_DSA_KeyGen", &[("seed", seed)], &[("param_set", ps)])
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

/// Helper: call verify and return the boolean result.
fn verify(
    harness: &mut Harness,
    pk: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<bool, TestOutcome> {
    let result = harness
        .call_fn(
            "ML_DSA_Verify",
            &[("pk", pk), ("message", msg), ("sigma", sig)],
            &[],
        )
        .map_err(|e| harness_error_to_outcome(&e))?;

    match result.get("valid") {
        Some(v) if v.len() >= 1 => Ok(v[0] == 0x01),
        _ => Err(TestOutcome::Error {
            message: "ML_DSA_Verify missing 'valid' output".into(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Test 1: Signature malleability — bit flips must cause rejection
// ---------------------------------------------------------------------------

struct SignatureMalleabilityTest;

impl TestCase for SignatureMalleabilityTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("verify-signature-malleability-{parameter_set}"),
            name: "Bit-flip in signature causes verification rejection".to_string(),
            bug_class: BugClass::new("dead-code", "missing-verification"),
            spec_ref: SpecReference::fips204("Algorithm 8 (ML-DSA.Verify_internal)"),
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

        let seed = [0x55u8; 32];
        let msg = b"malleability test message";

        let (pk, _sk, sig) = match generate_keypair_and_sig(harness, p, &seed, msg) {
            Ok(t) => t,
            Err(o) => return o,
        };

        // Sanity check: original signature must verify.
        match verify(harness, &pk, msg, &sig) {
            Ok(true) => {}
            Ok(false) => {
                return TestOutcome::Error {
                    message: "original signature failed verification (test setup error)".into(),
                };
            }
            Err(o) => return o,
        }

        // Flip single bits at strategic positions in the signature.
        // Signature layout: c_tilde || z || h
        let c_tilde_len = p.lambda / 4;
        let hint_len = p.omega + p.k;
        let z_start = c_tilde_len;
        let z_end = sig.len() - hint_len;

        let flip_positions = vec![
            ("c_tilde[0] bit 0", 0, 0),
            ("c_tilde[mid] bit 3", c_tilde_len / 2, 3),
            ("z[0] bit 0", z_start, 0),
            ("z[mid] bit 7", (z_start + z_end) / 2, 7),
            ("z[last] bit 0", z_end.saturating_sub(1), 0),
            ("h[0] bit 0", z_end, 0),
            ("last byte bit 0", sig.len() - 1, 0),
        ];

        for (label, byte_pos, bit_pos) in flip_positions {
            if byte_pos >= sig.len() {
                continue;
            }

            let mut bad_sig = sig.clone();
            bad_sig[byte_pos] ^= 1 << bit_pos;

            match verify(harness, &pk, msg, &bad_sig) {
                Ok(true) => {
                    return TestOutcome::Fail {
                        expected: "rejection (valid = 0x00)".into(),
                        actual: "verification succeeded (valid = 0x01)".into(),
                        detail: format!(
                            "Flipping {label} (byte {byte_pos}, bit {bit_pos}) in the signature \
                             did not cause rejection for {parameter_set}. The verifier may be \
                             skipping critical checks."
                        ),
                    };
                }
                Ok(false) => {} // correctly rejected
                Err(o) => return o,
            }
        }

        TestOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// Test 2: Wrong key rejection
// ---------------------------------------------------------------------------

struct WrongKeyRejectionTest;

impl TestCase for WrongKeyRejectionTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("verify-wrong-key-{parameter_set}"),
            name: "Signature under key A must fail under key B".to_string(),
            bug_class: BugClass::new("dead-code", "missing-verification"),
            spec_ref: SpecReference::fips204("Algorithm 8 (ML-DSA.Verify_internal)"),
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
        let msg = b"wrong key test message";

        // Generate keypair A and sign.
        let seed_a = [0xAAu8; 32];
        let (pk_a, _sk_a, sig_a) = match generate_keypair_and_sig(harness, p, &seed_a, msg) {
            Ok(t) => t,
            Err(o) => return o,
        };

        // Generate keypair B (different seed).
        let seed_b = [0xBBu8; 32];
        let kg_b = match harness.call_fn(
            "ML_DSA_KeyGen",
            &[("seed", &seed_b)],
            &[("param_set", ps)],
        ) {
            Ok(r) => r,
            Err(e) => return harness_error_to_outcome(&e),
        };
        let pk_b = match kg_b.get("pk") {
            Some(b) => b.clone(),
            None => return TestOutcome::Error {
                message: "keygen B missing pk".into(),
            },
        };

        // Sanity: sig_a verifies under pk_a.
        match verify(harness, &pk_a, msg, &sig_a) {
            Ok(true) => {}
            Ok(false) => {
                return TestOutcome::Error {
                    message: "signature A failed under pk_a (test setup error)".into(),
                };
            }
            Err(o) => return o,
        }

        // sig_a must NOT verify under pk_b.
        match verify(harness, &pk_b, msg, &sig_a) {
            Ok(true) => {
                return TestOutcome::Fail {
                    expected: "rejection (valid = 0x00)".into(),
                    actual: "verification succeeded (valid = 0x01)".into(),
                    detail: format!(
                        "A signature generated under key A was accepted under a different \
                         key B for {parameter_set}. This indicates the verifier is not \
                         binding the signature to the public key (rho, t1)."
                    ),
                };
            }
            Ok(false) => {} // correctly rejected
            Err(o) => return o,
        }

        TestOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// Test 3: Empty message
// ---------------------------------------------------------------------------

struct EmptyMessageTest;

impl TestCase for EmptyMessageTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("verify-empty-message-{parameter_set}"),
            name: "Sign and verify with empty message".to_string(),
            bug_class: BugClass::new("spec-divergence", "edge-case"),
            spec_ref: SpecReference::fips204("Algorithms 7-8"),
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

        let seed = [0xEEu8; 32];
        let empty_msg: &[u8] = b"";

        let (pk, _sk, sig) = match generate_keypair_and_sig(harness, p, &seed, empty_msg) {
            Ok(t) => t,
            Err(o) => return o,
        };

        // Verify the empty-message signature.
        match verify(harness, &pk, empty_msg, &sig) {
            Ok(true) => {}
            Ok(false) => {
                return TestOutcome::Fail {
                    expected: "valid = 0x01 (verification succeeds)".into(),
                    actual: "valid = 0x00 (verification failed)".into(),
                    detail: format!(
                        "Sign/Verify round-trip failed for an empty message on {parameter_set}. \
                         The implementation may not handle zero-length messages correctly \
                         when computing mu = H(tr || M')."
                    ),
                };
            }
            Err(o) => return o,
        }

        // The empty-message signature must NOT verify with a non-empty message.
        match verify(harness, &pk, b"not empty", &sig) {
            Ok(true) => {
                return TestOutcome::Fail {
                    expected: "rejection for different message".into(),
                    actual: "verification succeeded".into(),
                    detail: format!(
                        "A signature over an empty message was accepted for a non-empty \
                         message on {parameter_set}. The message hash binding may be broken."
                    ),
                };
            }
            Ok(false) => {} // correctly rejected
            Err(o) => return o,
        }

        TestOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// Test 4: Message integrity — single-byte modifications must invalidate
// ---------------------------------------------------------------------------

struct MessageIntegrityTest;

impl TestCase for MessageIntegrityTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("verify-message-integrity-{parameter_set}"),
            name: "Single-byte message modification causes verification rejection".to_string(),
            bug_class: BugClass::new("dead-code", "missing-message-binding"),
            spec_ref: SpecReference::fips204("Algorithm 8, line 7 (mu computation)"),
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

        let seed = [0x77u8; 32];
        // Use a message long enough to exercise multi-byte modification positions
        // and long enough to span multiple SHAKE256 absorb blocks (136 bytes).
        let msg: Vec<u8> = (0..200).map(|i| (i & 0xFF) as u8).collect();

        let (pk, _sk, sig) = match generate_keypair_and_sig(harness, p, &seed, &msg) {
            Ok(t) => t,
            Err(o) => return o,
        };

        // Sanity: original message verifies.
        match verify(harness, &pk, &msg, &sig) {
            Ok(true) => {}
            Ok(false) => {
                return TestOutcome::Error {
                    message: "original signature failed verification (test setup error)".into(),
                };
            }
            Err(o) => return o,
        }

        // Modify single bytes at strategic positions: first, middle, last,
        // and at the SHAKE256 block boundary (byte 135/136).
        let positions = [0, 1, 67, 135, 136, msg.len() - 2, msg.len() - 1];

        for &pos in &positions {
            if pos >= msg.len() {
                continue;
            }

            let mut bad_msg = msg.clone();
            bad_msg[pos] ^= 0x01; // flip lowest bit

            match verify(harness, &pk, &bad_msg, &sig) {
                Ok(true) => {
                    return TestOutcome::Fail {
                        expected: "rejection (valid = 0x00)".into(),
                        actual: "verification succeeded (valid = 0x01)".into(),
                        detail: format!(
                            "Modifying byte {pos} (0x{:02x} -> 0x{:02x}) of a {}-byte message \
                             did not cause verification rejection for {parameter_set}. The message \
                             representative mu = H(tr || M') may not incorporate all message bytes. \
                             Position {pos} is {}.",
                            msg[pos], bad_msg[pos], msg.len(),
                            if pos < 136 { "within the first SHAKE256 block" }
                            else { "beyond the first SHAKE256 block" }
                        ),
                    };
                }
                Ok(false) => {} // correctly rejected
                Err(o) => return o,
            }
        }

        TestOutcome::Pass
    }
}
