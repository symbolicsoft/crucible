use crucible_core::harness::Harness;
use crucible_core::orchestrator::{TestCase, TestCategory, harness_error_to_outcome};
use crucible_core::verdict::*;
use crate::math::ntt as ref_ntt;
use crate::math::kpke;
use crate::params::{self, N, Q};

pub fn category() -> TestCategory {
    TestCategory {
        name: "ntt".to_string(),
        tests: vec![
            // Direct internal tests (require harness to expose NTT/NTT_inv).
            Box::new(NttRoundTripTest),
            Box::new(ZetaOrderingTest),
            Box::new(MultiplyNttsTest),
            Box::new(NttMultiplyMatchesSchoolbookTest),
            // Black-box tests (work through top-level API — test NTT indirectly).
            Box::new(DeterministicKeygenTest),
            Box::new(DeterministicEncapsTest),
            Box::new(EncapsDecapsRoundTripTest),
        ],
    }
}

/// Encode a polynomial (256 coefficients mod q) as bytes: each coefficient as 2 LE bytes.
fn poly_to_bytes(f: &[u32; N]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(N * 2);
    for &coeff in f {
        bytes.extend_from_slice(&(coeff as u16).to_le_bytes());
    }
    bytes
}

/// Decode a polynomial from bytes (2 LE bytes per coefficient).
fn poly_from_bytes(bytes: &[u8]) -> Option<[u32; N]> {
    if bytes.len() != N * 2 {
        return None;
    }
    let mut f = [0u32; N];
    for i in 0..N {
        f[i] = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]) as u32;
    }
    Some(f)
}

// ===========================================================================
// Direct internal tests (require NTT/NTT_inv/MultiplyNTTs exposed)
// ===========================================================================

struct NttRoundTripTest;

impl TestCase for NttRoundTripTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("ntt-round-trip-{parameter_set}"),
            name: "NTT_inv(NTT(f)) == f for various polynomials".to_string(),
            bug_class: BugClass::new("spec-divergence", "ntt"),
            spec_ref: SpecReference::fips203("§4.3, Algorithms 9–10"),
            severity: Severity::Critical,
            provenance: None,
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        if params::params_by_name(parameter_set).is_none() {
            return TestOutcome::Error { message: format!("unknown parameter set: {parameter_set}") };
        }

        let test_polys = make_test_polynomials();

        for (name, f) in &test_polys {
            let f_bytes = poly_to_bytes(f);

            let ntt_result = match harness.call_fn("NTT", &[("f", &f_bytes)], &[]) {
                Ok(outputs) => match outputs.get("f_hat").and_then(|b| poly_from_bytes(b)) {
                    Some(p) => p,
                    None => return TestOutcome::Error {
                        message: format!("NTT returned invalid output for {name}"),
                    },
                },
                Err(e) => return harness_error_to_outcome(&e),
            };

            let ntt_result_bytes = poly_to_bytes(&ntt_result);
            let inv_result = match harness.call_fn("NTT_inv", &[("f_hat", &ntt_result_bytes)], &[]) {
                Ok(outputs) => match outputs.get("f").and_then(|b| poly_from_bytes(b)) {
                    Some(p) => p,
                    None => return TestOutcome::Error {
                        message: format!("NTT_inv returned invalid output for {name}"),
                    },
                },
                Err(e) => return harness_error_to_outcome(&e),
            };

            if inv_result != *f {
                let first_diff = f.iter().zip(inv_result.iter())
                    .position(|(a, b)| a != b).unwrap();
                return TestOutcome::Fail {
                    expected: format!("f[{first_diff}] = {}", f[first_diff]),
                    actual: format!("f[{first_diff}] = {}", inv_result[first_diff]),
                    detail: format!(
                        "NTT_inv(NTT(f)) != f for polynomial '{name}'. \
                         First divergence at index {first_diff}."
                    ),
                };
            }

            let expected_ntt = ref_ntt::ntt(f);
            if ntt_result != expected_ntt {
                let first_diff = expected_ntt.iter().zip(ntt_result.iter())
                    .position(|(a, b)| a != b).unwrap();
                return TestOutcome::Fail {
                    expected: format!("f_hat[{first_diff}] = {}", expected_ntt[first_diff]),
                    actual: format!("f_hat[{first_diff}] = {}", ntt_result[first_diff]),
                    detail: format!(
                        "NTT(f) diverges from reference for polynomial '{name}'. \
                         First divergence at index {first_diff}."
                    ),
                };
            }
        }

        TestOutcome::Pass
    }
}

struct ZetaOrderingTest;

impl TestCase for ZetaOrderingTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("ntt-zeta-ordering-{parameter_set}"),
            name: "NTT uses correct ζ^BitRev7(i) powers".to_string(),
            bug_class: BugClass::new("spec-divergence", "zeta-ordering"),
            spec_ref: SpecReference::fips203("§4.3, Appendix A"),
            severity: Severity::Critical,
            provenance: None,
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        if params::params_by_name(parameter_set).is_none() {
            return TestOutcome::Error { message: format!("unknown parameter set: {parameter_set}") };
        }

        for exp in [0, 1, 2, 7, 64, 127, 128, 255] {
            let mut f = [0u32; N];
            f[exp] = 1;
            let f_bytes = poly_to_bytes(&f);

            let ntt_result = match harness.call_fn("NTT", &[("f", &f_bytes)], &[]) {
                Ok(outputs) => match outputs.get("f_hat").and_then(|b| poly_from_bytes(b)) {
                    Some(p) => p,
                    None => return TestOutcome::Error {
                        message: format!("NTT invalid output for X^{exp}"),
                    },
                },
                Err(e) => return harness_error_to_outcome(&e),
            };

            let expected = ref_ntt::ntt(&f);
            if ntt_result != expected {
                let first_diff = expected.iter().zip(ntt_result.iter())
                    .position(|(a, b)| a != b).unwrap();
                return TestOutcome::Fail {
                    expected: format!("f_hat[{first_diff}] = {}", expected[first_diff]),
                    actual: format!("f_hat[{first_diff}] = {}", ntt_result[first_diff]),
                    detail: format!(
                        "NTT(X^{exp}) diverges from reference at index {first_diff}. \
                         This likely indicates incorrect zeta root ordering \
                         (FIPS 203 §4.3 requires ζ^BitRev7(i) powers)."
                    ),
                };
            }
        }

        TestOutcome::Pass
    }
}

struct MultiplyNttsTest;

impl TestCase for MultiplyNttsTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("ntt-multiply-{parameter_set}"),
            name: "MultiplyNTTs / BaseCaseMultiply correctness".to_string(),
            bug_class: BugClass::new("spec-divergence", "multiply-ntt"),
            spec_ref: SpecReference::fips203("§4.3.1, Algorithms 11–12"),
            severity: Severity::Critical,
            provenance: None,
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        if params::params_by_name(parameter_set).is_none() {
            return TestOutcome::Error { message: format!("unknown parameter set: {parameter_set}") };
        }

        let test_pairs = make_ntt_multiply_test_pairs();

        for (name, f_hat, g_hat) in &test_pairs {
            let result = match harness.call_fn(
                "MultiplyNTTs",
                &[("f_hat", &poly_to_bytes(f_hat)), ("g_hat", &poly_to_bytes(g_hat))],
                &[],
            ) {
                Ok(outputs) => match outputs.get("h_hat").and_then(|b| poly_from_bytes(b)) {
                    Some(p) => p,
                    None => return TestOutcome::Error {
                        message: format!("MultiplyNTTs invalid output for '{name}'"),
                    },
                },
                Err(e) => return harness_error_to_outcome(&e),
            };

            let expected = ref_ntt::multiply_ntts(f_hat, g_hat);
            if result != expected {
                let first_diff = expected.iter().zip(result.iter())
                    .position(|(a, b)| a != b).unwrap();
                return TestOutcome::Fail {
                    expected: format!("h_hat[{first_diff}] = {}", expected[first_diff]),
                    actual: format!("h_hat[{first_diff}] = {}", result[first_diff]),
                    detail: format!(
                        "MultiplyNTTs diverges for '{name}' at index {first_diff}. \
                         Check BaseCaseMultiply (Algorithm 12) and γ values."
                    ),
                };
            }
        }

        TestOutcome::Pass
    }
}

struct NttMultiplyMatchesSchoolbookTest;

impl TestCase for NttMultiplyMatchesSchoolbookTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("ntt-multiply-schoolbook-{parameter_set}"),
            name: "NTT_inv(MultiplyNTTs(NTT(f), NTT(g))) == f ×_{R_q} g".to_string(),
            bug_class: BugClass::new("spec-divergence", "multiply-correctness"),
            spec_ref: SpecReference::fips203("§4.3, Eq. 4.9"),
            severity: Severity::Critical,
            provenance: None,
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        if params::params_by_name(parameter_set).is_none() {
            return TestOutcome::Error { message: format!("unknown parameter set: {parameter_set}") };
        }

        let test_pairs = vec![
            ("1+X times 1+X", {
                let mut f = [0u32; N]; f[0] = 1; f[1] = 1; f
            }, {
                let mut g = [0u32; N]; g[0] = 1; g[1] = 1; g
            }),
            ("X^127 times X^128", {
                let mut f = [0u32; N]; f[127] = 1; f
            }, {
                let mut g = [0u32; N]; g[128] = 1; g
            }),
        ];

        for (name, f, g) in &test_pairs {
            let f_hat = match harness.call_fn("NTT", &[("f", &poly_to_bytes(f))], &[]) {
                Ok(o) => match o.get("f_hat").and_then(|b| poly_from_bytes(b)) {
                    Some(p) => p,
                    None => return TestOutcome::Error { message: format!("NTT failed for f in '{name}'") },
                },
                Err(e) => return harness_error_to_outcome(&e),
            };

            let g_hat = match harness.call_fn("NTT", &[("f", &poly_to_bytes(g))], &[]) {
                Ok(o) => match o.get("f_hat").and_then(|b| poly_from_bytes(b)) {
                    Some(p) => p,
                    None => return TestOutcome::Error { message: format!("NTT failed for g in '{name}'") },
                },
                Err(e) => return harness_error_to_outcome(&e),
            };

            let h_hat = match harness.call_fn(
                "MultiplyNTTs",
                &[("f_hat", &poly_to_bytes(&f_hat)), ("g_hat", &poly_to_bytes(&g_hat))],
                &[],
            ) {
                Ok(o) => match o.get("h_hat").and_then(|b| poly_from_bytes(b)) {
                    Some(p) => p,
                    None => return TestOutcome::Error { message: format!("MultiplyNTTs failed in '{name}'") },
                },
                Err(e) => return harness_error_to_outcome(&e),
            };

            let h = match harness.call_fn("NTT_inv", &[("f_hat", &poly_to_bytes(&h_hat))], &[]) {
                Ok(o) => match o.get("f").and_then(|b| poly_from_bytes(b)) {
                    Some(p) => p,
                    None => return TestOutcome::Error { message: format!("NTT_inv failed in '{name}'") },
                },
                Err(e) => return harness_error_to_outcome(&e),
            };

            let expected = ref_ntt::schoolbook_multiply(f, g);
            if h != expected {
                let first_diff = expected.iter().zip(h.iter())
                    .position(|(a, b)| a != b).unwrap();
                return TestOutcome::Fail {
                    expected: format!("h[{first_diff}] = {}", expected[first_diff]),
                    actual: format!("h[{first_diff}] = {}", h[first_diff]),
                    detail: format!(
                        "NTT_inv(MultiplyNTTs(NTT(f), NTT(g))) != f·g in R_q for '{name}'. \
                         Divergence at index {first_diff}."
                    ),
                };
            }
        }

        TestOutcome::Pass
    }
}

// ===========================================================================
// Black-box tests (work through top-level API — test NTT/compress/sampling
// indirectly by comparing full algorithm outputs)
// ===========================================================================

struct DeterministicKeygenTest;

impl TestCase for DeterministicKeygenTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("ntt-keygen-deterministic-{parameter_set}"),
            name: "Deterministic keygen matches reference (tests NTT, sampling, encoding)".to_string(),
            bug_class: BugClass::new("spec-divergence", "ntt"),
            spec_ref: SpecReference::fips203("§6.1, Algorithm 16"),
            severity: Severity::Critical,
            provenance: Some("Cryspen ML-KEM missing inverse NTT".to_string()),
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        let p = match params::params_by_name(parameter_set) {
            Some(p) => p,
            None => return TestOutcome::Error { message: format!("unknown: {parameter_set}") },
        };

        // Use deterministic seeds.
        let d = [0x42u8; 32];
        let z = [0x7Fu8; 32];
        let mut randomness = [0u8; 64];
        randomness[..32].copy_from_slice(&d);
        randomness[32..].copy_from_slice(&z);

        // Compute reference output.
        let ref_kp = kpke::ml_kem_keygen_internal(&d, &z, p);

        // Ask the harness.
        let result = harness.call_fn(
            "ML_KEM_KeyGen",
            &[("randomness", &randomness)],
            &[("param_set", match p.k { 2 => 512, 3 => 768, _ => 1024 })],
        );

        match result {
            Ok(outputs) => {
                let ek = match outputs.get("ek") {
                    Some(b) => b.clone(),
                    None => return TestOutcome::Error { message: "ML_KEM_KeyGen: missing 'ek'".into() },
                };
                let dk = match outputs.get("dk") {
                    Some(b) => b.clone(),
                    None => return TestOutcome::Error { message: "ML_KEM_KeyGen: missing 'dk'".into() },
                };

                if ek != ref_kp.ek {
                    // Find first differing byte.
                    let diff_pos = ek.iter().zip(ref_kp.ek.iter())
                        .position(|(a, b)| a != b)
                        .unwrap_or(ek.len().min(ref_kp.ek.len()));
                    return TestOutcome::Fail {
                        expected: format!("ek[{}] = 0x{:02x}", diff_pos, ref_kp.ek.get(diff_pos).copied().unwrap_or(0)),
                        actual: format!("ek[{}] = 0x{:02x}", diff_pos, ek.get(diff_pos).copied().unwrap_or(0)),
                        detail: format!(
                            "Deterministic keygen ({parameter_set}) produced a different \
                             encapsulation key at byte {diff_pos}. This indicates a bug in NTT, \
                             sampling (SampleNTT/SamplePolyCBD), or ByteEncode. \
                             ek lengths: got {}, expected {}.",
                            ek.len(), ref_kp.ek.len()
                        ),
                    };
                }

                if dk != ref_kp.dk {
                    let diff_pos = dk.iter().zip(ref_kp.dk.iter())
                        .position(|(a, b)| a != b)
                        .unwrap_or(dk.len().min(ref_kp.dk.len()));
                    return TestOutcome::Fail {
                        expected: format!("dk[{}] = 0x{:02x}", diff_pos, ref_kp.dk.get(diff_pos).copied().unwrap_or(0)),
                        actual: format!("dk[{}] = 0x{:02x}", diff_pos, dk.get(diff_pos).copied().unwrap_or(0)),
                        detail: format!(
                            "Deterministic keygen ({parameter_set}) produced a different \
                             decapsulation key at byte {diff_pos}. \
                             dk lengths: got {}, expected {}.",
                            dk.len(), ref_kp.dk.len()
                        ),
                    };
                }

                TestOutcome::Pass
            }
            Err(e) => harness_error_to_outcome(&e),
        }
    }
}

struct DeterministicEncapsTest;

impl TestCase for DeterministicEncapsTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("ntt-encaps-deterministic-{parameter_set}"),
            name: "Deterministic encaps matches reference (tests NTT, compress, encrypt)".to_string(),
            bug_class: BugClass::new("spec-divergence", "ntt"),
            spec_ref: SpecReference::fips203("§6.2, Algorithm 17"),
            severity: Severity::Critical,
            provenance: Some("Cryspen ML-KEM missing inverse NTT in encryption".to_string()),
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        let p = match params::params_by_name(parameter_set) {
            Some(p) => p,
            None => return TestOutcome::Error { message: format!("unknown: {parameter_set}") },
        };

        // Generate a key pair deterministically.
        let d = [0x42u8; 32];
        let z = [0x7Fu8; 32];
        let ref_kp = kpke::ml_kem_keygen_internal(&d, &z, p);

        // Encapsulate deterministically.
        let m = [0xABu8; 32];
        let (ref_ct, ref_ss) = kpke::ml_kem_encaps_internal(&ref_kp.ek, &m, p);

        // Ask the harness.
        let result = harness.call_fn(
            "ML_KEM_Encaps",
            &[("ek", &ref_kp.ek), ("randomness", &m)],
            &[],
        );

        match result {
            Ok(outputs) => {
                let ct = match outputs.get("c") {
                    Some(b) => b.clone(),
                    None => return TestOutcome::Error { message: "ML_KEM_Encaps: missing 'c'".into() },
                };
                let ss = match outputs.get("K") {
                    Some(b) => b.clone(),
                    None => return TestOutcome::Error { message: "ML_KEM_Encaps: missing 'K'".into() },
                };

                if ct != ref_ct {
                    let diff_pos = ct.iter().zip(ref_ct.iter())
                        .position(|(a, b)| a != b)
                        .unwrap_or(ct.len().min(ref_ct.len()));
                    return TestOutcome::Fail {
                        expected: format!("ct[{}] = 0x{:02x}", diff_pos, ref_ct.get(diff_pos).copied().unwrap_or(0)),
                        actual: format!("ct[{}] = 0x{:02x}", diff_pos, ct.get(diff_pos).copied().unwrap_or(0)),
                        detail: format!(
                            "Deterministic encaps ({parameter_set}) produced a different ciphertext \
                             at byte {diff_pos}. This indicates a bug in K-PKE.Encrypt — likely in \
                             NTT, compress, or sampling. ct lengths: got {}, expected {}.",
                            ct.len(), ref_ct.len()
                        ),
                    };
                }

                if ss != ref_ss {
                    return TestOutcome::Fail {
                        expected: format!("K = {}", hex::encode(&ref_ss)),
                        actual: format!("K = {}", hex::encode(&ss)),
                        detail: format!(
                            "Deterministic encaps ({parameter_set}) produced a different \
                             shared secret. This indicates a bug in the G hash or key derivation."
                        ),
                    };
                }

                TestOutcome::Pass
            }
            Err(e) => harness_error_to_outcome(&e),
        }
    }
}

struct EncapsDecapsRoundTripTest;

impl TestCase for EncapsDecapsRoundTripTest {
    fn meta(&self, parameter_set: &str) -> TestMeta {
        TestMeta {
            id: format!("ntt-encaps-decaps-roundtrip-{parameter_set}"),
            name: "Encaps then Decaps produces same shared secret".to_string(),
            bug_class: BugClass::new("spec-divergence", "ntt"),
            spec_ref: SpecReference::fips203("§3.2, correctness property"),
            severity: Severity::Critical,
            provenance: Some("Cryspen ML-KEM missing inverse NTT caused decaps failure".to_string()),
        }
    }

    fn run(&self, harness: &mut Harness, parameter_set: &str) -> TestOutcome {
        let p = match params::params_by_name(parameter_set) {
            Some(p) => p,
            None => return TestOutcome::Error { message: format!("unknown: {parameter_set}") },
        };

        // Step 1: Generate key pair via harness.
        let mut randomness = [0u8; 64];
        randomness[..32].copy_from_slice(&[0x11u8; 32]);
        randomness[32..].copy_from_slice(&[0x22u8; 32]);

        let keygen_result = harness.call_fn(
            "ML_KEM_KeyGen",
            &[("randomness", &randomness)],
            &[("param_set", match p.k { 2 => 512, 3 => 768, _ => 1024 })],
        );
        let (ek, dk) = match keygen_result {
            Ok(outputs) => {
                let ek = match outputs.get("ek") {
                    Some(b) => b.clone(),
                    None => return TestOutcome::Error { message: "keygen: missing 'ek'".into() },
                };
                let dk = match outputs.get("dk") {
                    Some(b) => b.clone(),
                    None => return TestOutcome::Error { message: "keygen: missing 'dk'".into() },
                };
                (ek, dk)
            }
            Err(e) => return harness_error_to_outcome(&e),
        };

        // Step 2: Encapsulate via harness.
        let m = [0x33u8; 32];
        let encaps_result = harness.call_fn(
            "ML_KEM_Encaps",
            &[("ek", &ek), ("randomness", &m)],
            &[],
        );
        let (ct, ss_encaps) = match encaps_result {
            Ok(outputs) => {
                let ct = match outputs.get("c") {
                    Some(b) => b.clone(),
                    None => return TestOutcome::Error { message: "encaps: missing 'c'".into() },
                };
                let ss = match outputs.get("K") {
                    Some(b) => b.clone(),
                    None => return TestOutcome::Error { message: "encaps: missing 'K'".into() },
                };
                (ct, ss)
            }
            Err(e) => return harness_error_to_outcome(&e),
        };

        // Step 3: Decapsulate via harness.
        let decaps_result = harness.call_fn(
            "ML_KEM_Decaps",
            &[("c", &ct), ("dk", &dk)],
            &[],
        );
        let ss_decaps = match decaps_result {
            Ok(outputs) => match outputs.get("K") {
                Some(b) => b.clone(),
                None => return TestOutcome::Error { message: "decaps: missing 'K'".into() },
            },
            Err(e) => return harness_error_to_outcome(&e),
        };

        // Step 4: Shared secrets must match.
        if ss_encaps != ss_decaps {
            return TestOutcome::Fail {
                expected: format!("K_encaps = {}", hex::encode(&ss_encaps)),
                actual: format!("K_decaps = {}", hex::encode(&ss_decaps)),
                detail: format!(
                    "Encaps and Decaps produced different shared secrets for {parameter_set}. \
                     This is a fundamental correctness failure — the most likely cause is a \
                     missing or incorrect inverse NTT in K-PKE.Decrypt (the Cryspen bug class)."
                ),
            };
        }

        if ss_encaps.len() != 32 {
            return TestOutcome::Fail {
                expected: "32-byte shared secret".into(),
                actual: format!("{}-byte shared secret", ss_encaps.len()),
                detail: "Shared secret must be exactly 32 bytes".into(),
            };
        }

        TestOutcome::Pass
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

fn make_test_polynomials() -> Vec<(&'static str, [u32; N])> {
    let mut polys = Vec::new();
    polys.push(("zero", [0u32; N]));
    let mut f = [0u32; N]; f[0] = 1;
    polys.push(("one", f));
    let mut f = [0u32; N]; f[1] = 1;
    polys.push(("X", f));
    let mut f = [0u32; N]; f[255] = 1;
    polys.push(("X^255", f));
    polys.push(("all-ones", [1u32; N]));
    polys.push(("all-max", [Q - 1; N]));
    let mut f = [0u32; N];
    for i in (1..N).step_by(2) { f[i] = Q - 1; }
    polys.push(("alternating", f));
    polys
}

fn make_ntt_multiply_test_pairs() -> Vec<(&'static str, [u32; N], [u32; N])> {
    let mut pairs = Vec::new();
    pairs.push(("zero*zero", [0u32; N], [0u32; N]));
    let one_hat = ref_ntt::ntt(&{
        let mut f = [0u32; N]; f[0] = 1; f
    });
    pairs.push(("f_hat*one_hat", one_hat, one_hat));
    let mut f_hat = [0u32; N];
    let mut g_hat = [0u32; N];
    let mut seed = 12345u64;
    for i in 0..N {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        f_hat[i] = (seed >> 33) as u32 % Q;
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        g_hat[i] = (seed >> 33) as u32 % Q;
    }
    pairs.push(("pseudo-random", f_hat, g_hat));
    pairs
}
