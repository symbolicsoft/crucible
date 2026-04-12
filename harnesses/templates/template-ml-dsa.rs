//! Crucible ML-DSA Harness Template — Rust
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

    // TODO: Update implementation name.
    // List only the functions your harness actually implements.
    // Crucible will skip tests that require unsupported functions.
    let handshake = Handshake {
        implementation: "your-implementation-name".to_string(),
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

    // TODO: Call your ML-DSA KeyGen_internal with the given seed and parameter set.
    // let (pk, sk) = match param_set {
    //     44 => your_ml_dsa_44_keygen_internal(&seed),
    //     65 => your_ml_dsa_65_keygen_internal(&seed),
    //     87 => your_ml_dsa_87_keygen_internal(&seed),
    //     _ => return err(format!("unsupported param_set: {param_set}")),
    // };
    let pk: Vec<u8> = todo!("ML_DSA_KeyGen");
    let sk: Vec<u8> = todo!("ML_DSA_KeyGen");

    let mut outputs = HashMap::new();
    outputs.insert("pk".into(), hex::encode(&pk));
    outputs.insert("sk".into(), hex::encode(&sk));
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
    // Param "param_set": 44, 65, or 87 (always provided by Crucible).
    // Output "signature": the encoded signature σ (byte string).
    //
    // The signing algorithm uses a rejection-sampling loop that may
    // require multiple iterations before producing a valid signature
    // (see FIPS 204, Appendix C for expected iteration counts).

    let sk = match get_bytes(req, "sk") { Ok(v) => v, Err(e) => return err(e) };
    let message = match get_bytes(req, "message") { Ok(v) => v, Err(e) => return err(e) };
    let rnd = match get_bytes(req, "rnd") { Ok(v) => v, Err(e) => return err(e) };
    let param_set = match get_param(req, "param_set") { Ok(v) => v, Err(e) => return err(e) };

    if rnd.len() != 32 {
        return err(format!("rnd must be 32 bytes, got {}", rnd.len()));
    }

    // TODO: Call your ML-DSA Sign_internal using param_set to select the variant.
    // let signature = match param_set {
    //     44 => your_ml_dsa_44_sign_internal(&sk, &message, &rnd),
    //     65 => your_ml_dsa_65_sign_internal(&sk, &message, &rnd),
    //     87 => your_ml_dsa_87_sign_internal(&sk, &message, &rnd),
    //     _ => return err(format!("unsupported param_set: {param_set}")),
    // };
    let signature: Vec<u8> = todo!("ML_DSA_Sign");

    let mut outputs = HashMap::new();
    outputs.insert("signature".into(), hex::encode(&signature));
    ok(outputs)
}

fn handle_verify(req: &Request) -> Response {
    // FIPS 204 §6.3, Algorithm 8: ML-DSA.Verify_internal(pk, M', σ)
    //
    // Input "pk": public key bytes.
    // Input "message": the formatted message M' (byte string).
    //   IMPORTANT: Same as for Sign — this is M', not the raw message.
    // Input "sigma": the signature σ (byte string).
    // Param "param_set": 44, 65, or 87 (always provided by Crucible).
    // Output "valid": single byte — 0x01 if valid, 0x00 if invalid.
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

    // TODO: Call your ML-DSA Verify_internal using param_set to select the variant.
    // let valid: bool = match param_set {
    //     44 => your_ml_dsa_44_verify_internal(&pk, &message, &sigma),
    //     65 => your_ml_dsa_65_verify_internal(&pk, &message, &sigma),
    //     87 => your_ml_dsa_87_verify_internal(&pk, &message, &sigma),
    //     _ => return err(format!("unsupported param_set: {param_set}")),
    // };
    let valid: bool = todo!("ML_DSA_Verify");

    let mut outputs = HashMap::new();
    outputs.insert("valid".into(), hex::encode([if valid { 0x01 } else { 0x00 }]));
    ok(outputs)
}
