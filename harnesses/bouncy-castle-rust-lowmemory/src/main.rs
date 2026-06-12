//! Crucible ML-DSA Harness Template — Rust adapted for calling Bouncy Castle Rust ML-DSA
//!
//! Wire your ML-DSA implementation to Crucible's test battery.
//! Reference: FIPS 204, Module-Lattice-Based Digital Signature Standard
//!            (https://doi.org/10.6028/NIST.FIPS.204)
//!
//! Build: cargo build --release
//! Run:   crucible ./target/release/your-harness --battery ml-dsa
//!
//! ## Architecture
//!
//! This harness targets the **internal** algorithms from FIPS 204 §6:
//!   - ML_DSA_KeyGen  → Algorithm 6  (ML-DSA.KeyGen_internal)
//!   - ML_DSA_Sign    → Algorithm 7  (ML-DSA.Sign_internal)
//!   - ML_DSA_Verify  → Algorithm 8  (ML-DSA.Verify_internal)
//!
//! NOT the external algorithms (§5, Algorithms 1–3), which add randomness
//! generation and domain-separated message encoding (M' construction).
//!
//! The "message" input sent by Crucible is the pre-formatted message
//! representative M' (a byte string passed directly to Sign_internal /
//! Verify_internal). It is NOT the raw application message M.
//!
//! If your library only exposes the external API (with a context string),
//! you can bridge to it: for "pure" ML-DSA with an empty context, the
//! external Sign/Verify prepend a 2-byte header (0x00 || 0x00) to M before
//! passing it to the internal function as M'. So you would need to strip
//! that 2-byte prefix from the "message" input to recover the raw M, then
//! call your external API with ctx = "" (the empty string). However, it is
//! preferable to call the internal API directly when possible.
//!
//! All sub-operations (NTT, Power2Round, Decompose, UseHint, MakeHint,
//! SampleInBall, etc.) are tested implicitly through these three functions.
//!
//! ## Protocol
//!
//! Communication is JSON-lines on stdin/stdout. All byte values are
//! hex-encoded. On startup, emit a handshake JSON line listing your
//! implementation name and supported functions. Then loop: read a request
//! line, write a response line.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};

use bouncycastle_core::traits::{SignaturePublicKey, SignaturePrivateKey, XOF};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_mldsa_lowmemory::{MLDSA44PrivateKey, MLDSA44PublicKey, MLDSA65PrivateKey, MLDSA65PublicKey, MLDSA87PrivateKey, MLDSA87PublicKey, MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait, MLDSATrait, MLDSA44, MLDSA65, MLDSA87};
use bouncycastle_sha3::SHAKE256;

#[derive(Deserialize)]
struct Request {
    function: String,
    #[serde(default)]
    inputs: HashMap<String, String>,
    #[serde(default)]
    params: HashMap<String, i64>,
}

#[derive(Serialize)]
struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    outputs: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    unsupported: bool,
}

#[derive(Serialize)]
struct Handshake {
    implementation: String,
    functions: Vec<String>,
}

fn main() {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    let handshake = Handshake {
        implementation: "bouncycastle-rust".to_string(),
        functions: vec![
            "ML_DSA_KeyGen".into(),
            "ML_DSA_Sign".into(),
            "ML_DSA_Verify".into(),
        ],
    };
    writeln!(out, "{}", serde_json::to_string(&handshake).unwrap()).unwrap();
    out.flush().unwrap();

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            break;
        }

        let req: Request = match serde_json::from_str(line.trim()) {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("invalid JSON: {e}");
                writeln!(out, "{}", serde_json::to_string(&Response {
                    outputs: None, error: Some(msg), unsupported: false,
                }).unwrap()).unwrap();
                out.flush().unwrap();
                continue;
            }
        };

        let resp = handle(&req);
        writeln!(out, "{}", serde_json::to_string(&resp).unwrap()).unwrap();
        out.flush().unwrap();
    }
}

fn handle(req: &Request) -> Response {
    match req.function.as_str() {
        "ML_DSA_KeyGen" => handle_keygen(req),
        "ML_DSA_Sign" => handle_sign(req),
        "ML_DSA_Verify" => handle_verify(req),
        _ => Response { outputs: None, error: None, unsupported: true },
    }
}

// ---- Helpers ----

fn get_bytes(req: &Request, key: &str) -> Result<Vec<u8>, String> {
    let h = req.inputs.get(key).ok_or(format!("missing '{key}'"))?;
    hex::decode(h).map_err(|e| format!("bad hex '{key}': {e}"))
}

fn get_param(req: &Request, key: &str) -> Result<i64, String> {
    req.params.get(key).copied().ok_or(format!("missing param '{key}'"))
}

fn ok(outputs: HashMap<String, String>) -> Response {
    Response { outputs: Some(outputs), error: None, unsupported: false }
}

fn err(msg: String) -> Response {
    Response { outputs: None, error: Some(msg), unsupported: false }
}

/// FIPS 204, Algorithm 7/8 line 6: µ = H(BytesToBits(tr) || M', 64).
/// Crucible sends the formatted message M'; bc-rust's *_mu APIs take µ.
fn compute_mu(tr: &[u8; 64], message: &[u8]) -> [u8; 64] {
    let mut h = SHAKE256::new();
    h.absorb(tr);
    h.absorb(message);
    let mut mu = [0u8; 64];
    h.squeeze_out(&mut mu);
    mu
}

/// Verify must reject malformed inputs, not crash (FIPS 204 §3.6.2).
fn reject() -> Response {
    let mut outputs = HashMap::new();
    outputs.insert("valid".into(), hex::encode([0x00u8]));
    ok(outputs)
}

// ---- Function handlers ----
//
// Key/signature byte sizes per parameter set (FIPS 204, Table 2):
//
//   Parameter set   pk bytes   sk bytes   sig bytes
//   ML-DSA-44       1312       2560       2420
//   ML-DSA-65       1952       4032       3309
//   ML-DSA-87       2592       4896       4627

fn handle_keygen(req: &Request) -> Response {
    // FIPS 204 §6.1, Algorithm 6: ML-DSA.KeyGen_internal(ξ)
    //
    // Input "seed": 32 bytes (ξ, the key-generation seed).
    // Param "param_set": 44, 65, or 87.
    // Output "pk": public key bytes, "sk": secret key bytes.
    //
    // This MUST be deterministic: the same ξ must always produce the
    // same (pk, sk) pair, exactly matching Algorithm 6 of the spec.
    // The seed is expanded via SHAKE256 (denoted H in the spec) to
    // derive ρ, ρ', and K, from which the key material is computed.

    let seed = match get_bytes(req, "seed") { Ok(v) => v, Err(e) => return err(e) };
    let param_set = match get_param(req, "param_set") { Ok(v) => v, Err(e) => return err(e) };

    if seed.len() != 32 {
        return err(format!("seed must be 32 bytes, got {}", seed.len()));
    }

    let mut outputs = HashMap::new();

    // Without allow_hazardous_operations, bc-rust classifies an all-zero
    // buffer as KeyType::Zeroized and keygen_internal refuses it. Crucible's
    // battery deliberately includes the all-zero seed (FIPS 204 Algorithm 6
    // accepts any 32-byte seed), so opt in: this is a conformance-testing
    // harness, not production key management.
    let mut seed_keymaterial = KeyMaterial::<32>::default();
    seed_keymaterial.allow_hazardous_operations();
    if let Err(e) = seed_keymaterial.set_bytes_as_type(seed.as_slice(), KeyType::Seed) {
        return err(format!("invalid seed: {e:?}"));
    }
    match param_set {
        44 => {
            let (pk, sk) = match MLDSA44::keygen_from_seed(&seed_keymaterial) {
                Ok(x) => x,
                Err(e) => return err(format!("keygen failed: {e:?}")),
            };
            outputs.insert("pk".into(), hex::encode(&pk.encode()));
            outputs.insert("sk".into(), hex::encode(&sk.encode_full_sk()));
        },
        65 => {
            let (pk, sk) = match MLDSA65::keygen_from_seed(&seed_keymaterial) {
                Ok(x) => x,
                Err(e) => return err(format!("keygen failed: {e:?}")),
            };
            outputs.insert("pk".into(), hex::encode(&pk.encode()));
            outputs.insert("sk".into(), hex::encode(&sk.encode_full_sk()));
        },
        87 => {
            let (pk, sk) = match MLDSA87::keygen_from_seed(&seed_keymaterial) {
                Ok(x) => x,
                Err(e) => return err(format!("keygen failed: {e:?}")),
            };
            outputs.insert("pk".into(), hex::encode(&pk.encode()));
            outputs.insert("sk".into(), hex::encode(&sk.encode_full_sk()));
        },
        _ => return err(format!("unsupported param_set: {param_set}")),
    };

    ok(outputs)
}

fn handle_sign(req: &Request) -> Response {
    // FIPS 204 §6.2, Algorithm 7: ML-DSA.Sign_internal(sk, M', rnd)
    //
    // Input "sk": secret key bytes (as returned by KeyGen).
    // Input "message": the formatted message M' (byte string).
    //   IMPORTANT: This is M', NOT the raw application message M.
    //   Pass these bytes directly to your Sign_internal. Do NOT apply
    //   any additional domain-separation encoding.
    // Input "rnd": 32 bytes.
    //   - Deterministic signing: rnd = {0}^32 (32 zero bytes).
    //   - Hedged signing: rnd = 32 fresh random bytes.
    //   (See FIPS 204 §3.4 for the distinction.)
    // Output "signature": the encoded signature σ (byte string).
    // Param "param_set": 44, 65, or 87.
    //
    // The signing algorithm uses a rejection-sampling loop that may
    // require multiple iterations before producing a valid signature
    // (see FIPS 204, Appendix C for expected iteration counts).

    let sk = match get_bytes(req, "sk") { Ok(v) => v, Err(e) => return err(e) };
    let message = match get_bytes(req, "message") { Ok(v) => v, Err(e) => return err(e) };
    let rnd = match get_bytes(req, "rnd") { Ok(v) => v, Err(e) => return err(e) };

    if rnd.len() != 32 {
        return err(format!("rnd must be 32 bytes, got {}", rnd.len()));
    }

    let param_set = match get_param(req, "param_set") { Ok(v) => v, Err(e) => return err(e) };
    let rnd: [u8; 32] = rnd.try_into().unwrap(); // length checked above

    let mut outputs = HashMap::new();

    match param_set {
        44 => {
            let sk = match MLDSA44PrivateKey::from_bytes(&sk) {
                Ok(k) => k,
                Err(e) => return err(format!("invalid sk: {e:?}")),
            };
            let mu = compute_mu(&sk.tr(), &message);
            let signature = match MLDSA44::sign_mu_deterministic(&sk, &mu, rnd) {
                Ok(s) => s,
                Err(e) => return err(format!("sign failed: {e:?}")),
            };
            outputs.insert("signature".into(), hex::encode(&signature));
        },
        65 => {
            let sk = match MLDSA65PrivateKey::from_bytes(&sk) {
                Ok(k) => k,
                Err(e) => return err(format!("invalid sk: {e:?}")),
            };
            let mu = compute_mu(&sk.tr(), &message);
            let signature = match MLDSA65::sign_mu_deterministic(&sk, &mu, rnd) {
                Ok(s) => s,
                Err(e) => return err(format!("sign failed: {e:?}")),
            };
            outputs.insert("signature".into(), hex::encode(&signature));
        },
        87 => {
            let sk = match MLDSA87PrivateKey::from_bytes(&sk) {
                Ok(k) => k,
                Err(e) => return err(format!("invalid sk: {e:?}")),
            };
            let mu = compute_mu(&sk.tr(), &message);
            let signature = match MLDSA87::sign_mu_deterministic(&sk, &mu, rnd) {
                Ok(s) => s,
                Err(e) => return err(format!("sign failed: {e:?}")),
            };
            outputs.insert("signature".into(), hex::encode(&signature));
        },
        _ => return err(format!("unsupported param_set: {param_set}")),
    };
    ok(outputs)
}

fn handle_verify(req: &Request) -> Response {
    // FIPS 204 §6.3, Algorithm 8: ML-DSA.Verify_internal(pk, M', σ)
    //
    // Input "pk": public key bytes.
    // Input "message": the formatted message M' (byte string).
    //   IMPORTANT: Same as for Sign — this is M', not the raw message.
    // Input "sigma": the signature σ (byte string).
    // Output "valid": single byte — 0x01 if valid, 0x00 if invalid.
    // Param "param_set": 44, 65, or 87.
    //
    // Per FIPS 204 §3.6.2: implementations that accept pk or σ of
    // non-standard length SHALL return false (not an error).
    // Return "valid" = 0x00 for any malformed input, wrong-length
    // keys/signatures, or invalid signatures — do NOT return an error
    // response, as the battery tests expect a boolean result.

    let pk = match get_bytes(req, "pk") { Ok(v) => v, Err(e) => return err(e) };
    let message = match get_bytes(req, "message") { Ok(v) => v, Err(e) => return err(e) };
    let sigma = match get_bytes(req, "sigma") { Ok(v) => v, Err(e) => return err(e) };

    let param_set = match get_param(req, "param_set") { Ok(v) => v, Err(e) => return err(e) };

    let valid: bool = match param_set {
        44 => {
            let pk = match MLDSA44PublicKey::from_bytes(&pk) {
                Ok(k) => k,
                Err(_) => return reject(),
            };
            let sig = match sigma.as_slice().try_into() {
                Ok(s) => s,
                Err(_) => return reject(),
            };
            let mu = compute_mu(&pk.compute_tr(), &message);
            MLDSA44::verify_mu_internal(&pk, &mu, sig)
        },
        65 => {
            let pk = match MLDSA65PublicKey::from_bytes(&pk) {
                Ok(k) => k,
                Err(_) => return reject(),
            };
            let sig = match sigma.as_slice().try_into() {
                Ok(s) => s,
                Err(_) => return reject(),
            };
            let mu = compute_mu(&pk.compute_tr(), &message);
            MLDSA65::verify_mu_internal(&pk, &mu, sig)
        },
        87 => {
            let pk = match MLDSA87PublicKey::from_bytes(&pk) {
                Ok(k) => k,
                Err(_) => return reject(),
            };
            let sig = match sigma.as_slice().try_into() {
                Ok(s) => s,
                Err(_) => return reject(),
            };
            let mu = compute_mu(&pk.compute_tr(), &message);
            MLDSA87::verify_mu_internal(&pk, &mu, sig)
        },
        _ => return err(format!("unsupported param_set: {param_set}")),
    };

    let mut outputs = HashMap::new();
    outputs.insert("valid".into(), hex::encode([if valid { 0x01 } else { 0x00 }]));
    ok(outputs)
}
