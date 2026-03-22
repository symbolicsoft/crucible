//! Crucible ML-KEM Harness Template — Rust
//!
//! Fill in the TODO sections to wire your ML-KEM implementation to Crucible.
//! Each function receives hex-decoded byte inputs and returns hex-encoded outputs.
//!
//! Build: cargo build --release
//! Run:   crucible ./target/release/your-harness

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
// Each handler receives inputs as hex-decoded bytes and returns outputs as hex strings.
// Polynomials are encoded as 512 bytes: 256 coefficients × 2 bytes little-endian each.

fn handle_compress_d(req: &Request) -> Response {
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
    // Input "F": 512 bytes (256 × u16 LE). Param "d": bit width.
    // Output "B": 32*d bytes.
    todo!("ByteEncode_d")
}

fn handle_byte_decode_d(req: &Request) -> Response {
    // Input "B": 32*d bytes. Param "d": bit width.
    // Output "F": 512 bytes (256 × u16 LE).
    todo!("ByteDecode_d")
}

fn handle_ntt(req: &Request) -> Response {
    // Input "f": 512 bytes (polynomial). Output "f_hat": 512 bytes (NTT representation).
    // Must produce FIPS 203 spec-standard NTT output (not Montgomery domain).
    todo!("NTT")
}

fn handle_ntt_inv(req: &Request) -> Response {
    // Input "f_hat": 512 bytes (NTT). Output "f": 512 bytes (polynomial).
    todo!("NTT_inv")
}

fn handle_multiply_ntts(req: &Request) -> Response {
    // Input "f_hat", "g_hat": 512 bytes each. Output "h_hat": 512 bytes.
    todo!("MultiplyNTTs")
}

fn handle_sample_poly_cbd(req: &Request) -> Response {
    // Input "B": 64*eta bytes. Param "eta": 2 or 3. Output "f": 512 bytes.
    todo!("SamplePolyCBD")
}

fn handle_sample_ntt(req: &Request) -> Response {
    // Input "B": 34 bytes (seed). Output "a_hat": 512 bytes.
    todo!("SampleNTT")
}

fn handle_keygen(req: &Request) -> Response {
    // Input "randomness": 64 bytes (d||z). Param "param_set": 512/768/1024.
    // Output "ek": encapsulation key bytes, "dk": decapsulation key bytes.
    todo!("ML_KEM_KeyGen")
}

fn handle_encaps(req: &Request) -> Response {
    // Input "ek": encapsulation key, "randomness": 32 bytes (message m).
    // Output "c": ciphertext, "K": 32-byte shared secret.
    todo!("ML_KEM_Encaps")
}

fn handle_decaps(req: &Request) -> Response {
    // Input "c": ciphertext, "dk": decapsulation key.
    // Output "K": 32-byte shared secret (or implicit rejection value).
    todo!("ML_KEM_Decaps")
}
