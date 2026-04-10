//! Crucible ML-KEM Harness Template — Rust
//!
//! Wire your ML-KEM implementation to Crucible's test battery.
//! Reference: FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism
//!            (https://doi.org/10.6028/NIST.FIPS.203)
//!
//! Build: cargo build --release
//! Run:   crucible ./target/release/your-harness --battery ml-kem
//!
//! ## Architecture
//!
//! The battery tests functions at two levels:
//!
//! **Low-level (auxiliary algorithms, FIPS 203 §4):**
//!   - Compress_d / Decompress_d  (§4.2.1, Eq 4.7–4.8)
//!   - ByteEncode_d / ByteDecode_d  (Algorithms 5–6)
//!   - NTT / NTT_inv  (Algorithms 9–10)
//!   - MultiplyNTTs  (Algorithm 11)
//!   - SamplePolyCBD  (Algorithm 8)
//!   - SampleNTT  (Algorithm 7)
//!
//! **High-level (internal algorithms, FIPS 203 §6):**
//!   - ML_KEM_KeyGen  → Algorithm 16  (ML-KEM.KeyGen_internal)
//!   - ML_KEM_Encaps  → Algorithm 17  (ML-KEM.Encaps_internal)
//!   - ML_KEM_Decaps  → Algorithm 18  (ML-KEM.Decaps_internal)
//!
//! These are the **internal** algorithms (§6), not the external ones (§7,
//! Algorithms 19–21). The internal algorithms are deterministic — all
//! randomness is provided as explicit input by the battery.
//!
//! You do NOT need to implement every function. List only the functions
//! your harness supports in the handshake; Crucible skips tests for
//! unsupported functions. However, the high-level functions (KeyGen,
//! Encaps, Decaps) provide the most valuable coverage.
//!
//! ## Protocol
//!
//! Communication is JSON-lines on stdin/stdout. All byte values are
//! hex-encoded. On startup, emit a handshake JSON line listing your
//! implementation name and supported functions. Then loop: read a request
//! line, write a response line. Polynomials are encoded as 512 bytes:
//! 256 coefficients, each as 2 bytes little-endian.

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

    // TODO: Update implementation name and list of supported functions.
    let handshake = Handshake {
        implementation: "your-implementation-name".to_string(),
        functions: vec![
            // List only the functions your harness actually implements.
            // Remove any you don't support — Crucible will skip those tests.
            "Compress_d".into(),
            "Decompress_d".into(),
            "ByteEncode_d".into(),
            "ByteDecode_d".into(),
            "NTT".into(),
            "NTT_inv".into(),
            "MultiplyNTTs".into(),
            "SamplePolyCBD".into(),
            "SampleNTT".into(),
            "ML_KEM_KeyGen".into(),
            "ML_KEM_Encaps".into(),
            "ML_KEM_Decaps".into(),
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
        "Compress_d" => handle_compress_d(req),
        "Decompress_d" => handle_decompress_d(req),
        "ByteEncode_d" => handle_byte_encode_d(req),
        "ByteDecode_d" => handle_byte_decode_d(req),
        "NTT" => handle_ntt(req),
        "NTT_inv" => handle_ntt_inv(req),
        "MultiplyNTTs" => handle_multiply_ntts(req),
        "SamplePolyCBD" => handle_sample_poly_cbd(req),
        "SampleNTT" => handle_sample_ntt(req),
        "ML_KEM_KeyGen" => handle_keygen(req),
        "ML_KEM_Encaps" => handle_encaps(req),
        "ML_KEM_Decaps" => handle_decaps(req),
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
// Key/ciphertext byte sizes per parameter set (FIPS 203, Table 3):
//
//   Parameter set    ek bytes   dk bytes   ct bytes   ss bytes
//   ML-KEM-512       800        1632       768        32
//   ML-KEM-768       1184       2400       1088       32
//   ML-KEM-1024      1568       3168       1568       32
//
// Global constants: n = 256, q = 3329, ζ = 17.

// --- Low-level auxiliary functions ---

fn handle_compress_d(req: &Request) -> Response {
    // FIPS 203 §4.2.1, Eq 4.7: Compress_d(x) = ⌈(2^d / q) · x⌋ mod 2^d
    //
    // Input "x": 2 bytes LE (coefficient in [0, q-1]).
    // Param "d": bit width, 1 ≤ d ≤ 11.
    // Output "y": 2 bytes LE (compressed value in [0, 2^d - 1]).
    //
    // IMPORTANT: Must use integer arithmetic only (§3.3).

    let d = match get_param(req, "d") { Ok(v) => v as u32, Err(e) => return err(e) };
    let x_bytes = match get_bytes(req, "x") { Ok(v) => v, Err(e) => return err(e) };
    let x = u16::from_le_bytes([x_bytes[0], x_bytes.get(1).copied().unwrap_or(0)]) as u32;

    // TODO: Call your implementation's Compress_d(x, d).
    let y: u32 = todo!("compress_d(x, d)");

    let mut out = HashMap::new();
    out.insert("y".into(), hex::encode((y as u16).to_le_bytes()));
    ok(out)
}

fn handle_decompress_d(req: &Request) -> Response {
    // FIPS 203 §4.2.1, Eq 4.8: Decompress_d(y) = ⌈(q / 2^d) · y⌋
    //
    // Input "y": 2 bytes LE (compressed value in [0, 2^d - 1]).
    // Param "d": bit width, 1 ≤ d ≤ 11.
    // Output "x": 2 bytes LE (decompressed coefficient in [0, q-1]).
    //
    // Property: Compress_d(Decompress_d(y)) = y for all valid y and d.

    let d = match get_param(req, "d") { Ok(v) => v as u32, Err(e) => return err(e) };
    let y_bytes = match get_bytes(req, "y") { Ok(v) => v, Err(e) => return err(e) };
    let y = u16::from_le_bytes([y_bytes[0], y_bytes.get(1).copied().unwrap_or(0)]) as u32;

    // TODO: Call your implementation's Decompress_d(y, d).
    let x: u32 = todo!("decompress_d(y, d)");

    let mut out = HashMap::new();
    out.insert("x".into(), hex::encode((x as u16).to_le_bytes()));
    ok(out)
}

fn handle_byte_encode_d(req: &Request) -> Response {
    // FIPS 203 §4.2.1, Algorithm 5: ByteEncode_d(F) → B
    //
    // Input "F": 512 bytes (256 coefficients × 2 bytes LE, each mod 2^d or mod q for d=12).
    // Param "d": bit width, 1 ≤ d ≤ 12.
    // Output "B": 32·d bytes (packed bit encoding).
    todo!("ByteEncode_d")
}

fn handle_byte_decode_d(req: &Request) -> Response {
    // FIPS 203 §4.2.1, Algorithm 6: ByteDecode_d(B) → F
    //
    // Input "B": 32·d bytes.
    // Param "d": bit width, 1 ≤ d ≤ 12.
    // Output "F": 512 bytes (256 coefficients × 2 bytes LE).
    //
    // For d = 12: output coefficients are reduced mod q (not mod 2^12).
    todo!("ByteDecode_d")
}

fn handle_ntt(req: &Request) -> Response {
    // FIPS 203 §4.3, Algorithm 9: NTT(f) → f_hat
    //
    // Input "f": 512 bytes (polynomial in R_q).
    // Output "f_hat": 512 bytes (NTT representation in T_q).
    //
    // Must produce FIPS 203 spec-standard NTT output using ζ = 17
    // with BitRev_7 ordering (NOT Montgomery domain).
    todo!("NTT")
}

fn handle_ntt_inv(req: &Request) -> Response {
    // FIPS 203 §4.3, Algorithm 10: NTT^{-1}(f_hat) → f
    //
    // Input "f_hat": 512 bytes (NTT representation).
    // Output "f": 512 bytes (polynomial).
    //
    // Final multiplication by 128^{-1} = 3303 mod q is required.
    todo!("NTT_inv")
}

fn handle_multiply_ntts(req: &Request) -> Response {
    // FIPS 203 §4.3.1, Algorithm 11: MultiplyNTTs(f_hat, g_hat) → h_hat
    //
    // Input "f_hat", "g_hat": 512 bytes each (NTT representations).
    // Output "h_hat": 512 bytes (product in T_q).
    //
    // Uses BaseCaseMultiply (Algorithm 12) on 128 pairs of degree-1
    // polynomials with gammas ζ^{2·BitRev_7(i)+1} for i = 0..127.
    todo!("MultiplyNTTs")
}

fn handle_sample_poly_cbd(req: &Request) -> Response {
    // FIPS 203 §4.2.2, Algorithm 8: SamplePolyCBD_η(B) → f
    //
    // Input "B": 64·η bytes (pseudorandom seed).
    // Param "eta": 2 or 3.
    // Output "f": 512 bytes (polynomial with small coefficients).
    //
    // Each coefficient is in [-η, η] (represented mod q as [0, η] ∪ [q-η, q-1]).
    todo!("SamplePolyCBD")
}

fn handle_sample_ntt(req: &Request) -> Response {
    // FIPS 203 §4.2.2, Algorithm 7: SampleNTT(B) → a_hat
    //
    // Input "B": 34 bytes (32-byte seed ρ + 2 index bytes j, i).
    // Output "a_hat": 512 bytes (element of T_q via rejection sampling).
    //
    // All output coefficients must be < q = 3329 (rejection sampling
    // rejects 12-bit values ≥ q from the SHAKE128 XOF stream).
    todo!("SampleNTT")
}

// --- High-level internal algorithms ---

fn handle_keygen(req: &Request) -> Response {
    // FIPS 203 §6.1, Algorithm 16: ML-KEM.KeyGen_internal(d, z)
    //
    // Input "randomness": 64 bytes (d || z, where d and z are each 32 bytes).
    //   d is the K-PKE seed; z is the implicit-rejection randomness.
    // Param "param_set": 512, 768, or 1024.
    // Output "ek": encapsulation key bytes, "dk": decapsulation key bytes.
    //
    // This MUST be deterministic: the same (d, z) must always produce
    // the same (ek, dk) pair. The dk includes: dk_PKE || ek || H(ek) || z.
    todo!("ML_KEM_KeyGen")
}

fn handle_encaps(req: &Request) -> Response {
    // FIPS 203 §6.2, Algorithm 17: ML-KEM.Encaps_internal(ek, m)
    //
    // Input "ek": encapsulation key (as returned by KeyGen).
    // Input "randomness": 32 bytes (message m used to derive K and r).
    // Output "c": ciphertext, "K": 32-byte shared secret.
    //
    // The encapsulation key SHOULD be validated first (§7.2):
    //   ByteEncode_12(ByteDecode_12(ek[0:384k])) must equal ek[0:384k].
    // If the check fails, return an error.
    todo!("ML_KEM_Encaps")
}

fn handle_decaps(req: &Request) -> Response {
    // FIPS 203 §6.3, Algorithm 18: ML-KEM.Decaps_internal(dk, c)
    //
    // Input "c": ciphertext.
    // Input "dk": decapsulation key.
    // Output "K": 32-byte shared secret.
    //
    // Implements the Fujisaki-Okamoto transform with implicit rejection:
    // if re-encryption of the decrypted plaintext does not match the
    // input ciphertext, output K_bar = J(z || c) instead of the real K.
    // The comparison MUST be constant-time (no timing side-channel).
    //
    // MUST always return a 32-byte "K" — never return an error for
    // invalid ciphertexts (that would leak the rejection decision).
    todo!("ML_KEM_Decaps")
}
