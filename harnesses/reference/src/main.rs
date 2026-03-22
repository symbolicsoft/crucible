use crucible_ml_kem::math::{compress, encode, kpke, ntt, sampling};
use crucible_ml_kem::params::{self, N, Q};
use serde::{Deserialize, Serialize};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;
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

    // Send handshake.
    let handshake = Handshake {
        implementation: "crucible-reference-ml-kem".to_string(),
        functions: vec![
            "Compress_d".into(),
            "Decompress_d".into(),
            "ByteEncode_d".into(),
            "ByteDecode_d".into(),
            "NTT".into(),
            "NTT_inv".into(),
            "MultiplyNTTs".into(),
            "BaseCaseMultiply".into(),
            "SamplePolyCBD".into(),
            "SampleNTT".into(),
            "ML_KEM_KeyGen".into(),
            "ML_KEM_Encaps".into(),
            "ML_KEM_Decaps".into(),
        ],
    };
    let line = serde_json::to_string(&handshake).unwrap();
    writeln!(out, "{line}").unwrap();
    out.flush().unwrap();

    // Process requests.
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let line = line.trim().to_string();
        if line.is_empty() {
            break;
        }

        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response {
                    outputs: None,
                    error: Some(format!("invalid request JSON: {e}")),
                    unsupported: false,
                };
                writeln!(out, "{}", serde_json::to_string(&resp).unwrap()).unwrap();
                out.flush().unwrap();
                continue;
            }
        };

        let resp = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handle_request(&req)
        })) {
            Ok(r) => r,
            Err(e) => {
                let msg = if let Some(s) = e.downcast_ref::<String>() {
                    s.clone()
                } else if let Some(s) = e.downcast_ref::<&str>() {
                    s.to_string()
                } else {
                    "harness panicked".to_string()
                };
                err_response(format!("internal error: {msg}"))
            }
        };
        writeln!(out, "{}", serde_json::to_string(&resp).unwrap()).unwrap();
        out.flush().unwrap();
    }
}

fn handle_request(req: &Request) -> Response {
    match req.function.as_str() {
        "Compress_d" => handle_compress_d(req),
        "Decompress_d" => handle_decompress_d(req),
        "ByteEncode_d" => handle_byte_encode(req),
        "ByteDecode_d" => handle_byte_decode(req),
        "NTT" => handle_ntt(req),
        "NTT_inv" => handle_inv_ntt(req),
        "MultiplyNTTs" => handle_multiply_ntts(req),
        "BaseCaseMultiply" => handle_base_case_multiply(req),
        "SamplePolyCBD" => handle_sample_poly_cbd(req),
        "SampleNTT" => handle_sample_ntt(req),
        "ML_KEM_KeyGen" => handle_ml_kem_keygen(req),
        "ML_KEM_Encaps" => handle_ml_kem_encaps(req),
        "ML_KEM_Decaps" => handle_ml_kem_decaps(req),
        _ => Response {
            outputs: None,
            error: None,
            unsupported: true,
        },
    }
}

// ---- Helper functions ----

fn get_input_bytes(req: &Request, key: &str) -> Result<Vec<u8>, String> {
    let hex_str = req
        .inputs
        .get(key)
        .ok_or_else(|| format!("missing input '{key}'"))?;
    hex::decode(hex_str).map_err(|e| format!("invalid hex in input '{key}': {e}"))
}

fn get_param(req: &Request, key: &str) -> Result<i64, String> {
    req.params
        .get(key)
        .copied()
        .ok_or_else(|| format!("missing param '{key}'"))
}

fn ok_outputs(outputs: HashMap<String, String>) -> Response {
    Response {
        outputs: Some(outputs),
        error: None,
        unsupported: false,
    }
}

fn err_response(msg: String) -> Response {
    Response {
        outputs: None,
        error: Some(msg),
        unsupported: false,
    }
}

fn coeff_from_le_bytes(bytes: &[u8]) -> u32 {
    if bytes.len() >= 2 {
        u16::from_le_bytes([bytes[0], bytes[1]]) as u32
    } else if bytes.len() == 1 {
        bytes[0] as u32
    } else {
        0
    }
}

fn coeff_to_le_bytes(val: u32) -> Vec<u8> {
    (val as u16).to_le_bytes().to_vec()
}

fn poly_from_bytes(bytes: &[u8]) -> Result<[u32; N], String> {
    if bytes.len() != N * 2 {
        return Err(format!(
            "polynomial must be {} bytes, got {}",
            N * 2,
            bytes.len()
        ));
    }
    let mut f = [0u32; N];
    for i in 0..N {
        f[i] = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]) as u32;
    }
    Ok(f)
}

fn poly_to_bytes(f: &[u32; N]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(N * 2);
    for &coeff in f {
        bytes.extend_from_slice(&(coeff as u16).to_le_bytes());
    }
    bytes
}

// ---- Function handlers ----

fn handle_compress_d(req: &Request) -> Response {
    let d = match get_param(req, "d") {
        Ok(d) => d as u32,
        Err(e) => return err_response(e),
    };
    let x_bytes = match get_input_bytes(req, "x") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };

    if d < 1 || d > 11 {
        return err_response(format!("d must be in [1, 11], got {d}"));
    }

    let x = coeff_from_le_bytes(&x_bytes);
    if x >= Q {
        return err_response(format!("x must be < q={Q}, got {x}"));
    }

    let y = compress::compress_d(x, d);
    let mut outputs = HashMap::new();
    outputs.insert("y".to_string(), hex::encode(coeff_to_le_bytes(y)));
    ok_outputs(outputs)
}

fn handle_decompress_d(req: &Request) -> Response {
    let d = match get_param(req, "d") {
        Ok(d) => d as u32,
        Err(e) => return err_response(e),
    };
    let y_bytes = match get_input_bytes(req, "y") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };

    if d < 1 || d > 11 {
        return err_response(format!("d must be in [1, 11], got {d}"));
    }

    let y = coeff_from_le_bytes(&y_bytes);
    if y >= (1 << d) {
        return err_response(format!("y must be < 2^{d}, got {y}"));
    }

    let x = compress::decompress_d(y, d);
    let mut outputs = HashMap::new();
    outputs.insert("x".to_string(), hex::encode(coeff_to_le_bytes(x)));
    ok_outputs(outputs)
}

fn handle_byte_encode(req: &Request) -> Response {
    let d = match get_param(req, "d") {
        Ok(d) => d as u32,
        Err(e) => return err_response(e),
    };
    let f_bytes = match get_input_bytes(req, "F") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };

    let f = match poly_from_bytes(&f_bytes) {
        Ok(f) => f,
        Err(e) => return err_response(e),
    };

    let encoded = encode::byte_encode(&f, d);
    let mut outputs = HashMap::new();
    outputs.insert("B".to_string(), hex::encode(&encoded));
    ok_outputs(outputs)
}

fn handle_byte_decode(req: &Request) -> Response {
    let d = match get_param(req, "d") {
        Ok(d) => d as u32,
        Err(e) => return err_response(e),
    };
    let b = match get_input_bytes(req, "B") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };

    let expected_len = 32 * d as usize;
    if b.len() != expected_len {
        return err_response(format!(
            "ByteDecode_{d} expects {expected_len} bytes, got {}",
            b.len()
        ));
    }

    let f = encode::byte_decode(&b, d);
    let mut outputs = HashMap::new();
    outputs.insert("F".to_string(), hex::encode(poly_to_bytes(&f)));
    ok_outputs(outputs)
}

fn handle_ntt(req: &Request) -> Response {
    let f_bytes = match get_input_bytes(req, "f") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };

    let f = match poly_from_bytes(&f_bytes) {
        Ok(f) => f,
        Err(e) => return err_response(e),
    };

    let f_hat = ntt::ntt(&f);
    let mut outputs = HashMap::new();
    outputs.insert("f_hat".to_string(), hex::encode(poly_to_bytes(&f_hat)));
    ok_outputs(outputs)
}

fn handle_inv_ntt(req: &Request) -> Response {
    let f_hat_bytes = match get_input_bytes(req, "f_hat") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };

    let f_hat = match poly_from_bytes(&f_hat_bytes) {
        Ok(f) => f,
        Err(e) => return err_response(e),
    };

    let f = ntt::inv_ntt(&f_hat);
    let mut outputs = HashMap::new();
    outputs.insert("f".to_string(), hex::encode(poly_to_bytes(&f)));
    ok_outputs(outputs)
}

fn handle_multiply_ntts(req: &Request) -> Response {
    let f_bytes = match get_input_bytes(req, "f_hat") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };
    let g_bytes = match get_input_bytes(req, "g_hat") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };

    let f_hat = match poly_from_bytes(&f_bytes) {
        Ok(f) => f,
        Err(e) => return err_response(format!("f_hat: {e}")),
    };
    let g_hat = match poly_from_bytes(&g_bytes) {
        Ok(g) => g,
        Err(e) => return err_response(format!("g_hat: {e}")),
    };

    let h_hat = ntt::multiply_ntts(&f_hat, &g_hat);
    let mut outputs = HashMap::new();
    outputs.insert("h_hat".to_string(), hex::encode(poly_to_bytes(&h_hat)));
    ok_outputs(outputs)
}

fn handle_base_case_multiply(req: &Request) -> Response {
    let a_bytes = match get_input_bytes(req, "a") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };
    let b_bytes = match get_input_bytes(req, "b") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };
    let gamma_bytes = match get_input_bytes(req, "gamma") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };

    if a_bytes.len() < 4 || b_bytes.len() < 4 {
        return err_response("a and b must each be 4 bytes (two coefficients)".into());
    }

    let a0 = u16::from_le_bytes([a_bytes[0], a_bytes[1]]) as u32;
    let a1 = u16::from_le_bytes([a_bytes[2], a_bytes[3]]) as u32;
    let b0 = u16::from_le_bytes([b_bytes[0], b_bytes[1]]) as u32;
    let b1 = u16::from_le_bytes([b_bytes[2], b_bytes[3]]) as u32;
    let gamma = coeff_from_le_bytes(&gamma_bytes);

    let (c0, c1) = ntt::base_case_multiply(a0, a1, b0, b1, gamma);

    let mut c_bytes = Vec::with_capacity(4);
    c_bytes.extend_from_slice(&(c0 as u16).to_le_bytes());
    c_bytes.extend_from_slice(&(c1 as u16).to_le_bytes());

    let mut outputs = HashMap::new();
    outputs.insert("c".to_string(), hex::encode(&c_bytes));
    ok_outputs(outputs)
}

fn handle_sample_poly_cbd(req: &Request) -> Response {
    let eta = match get_param(req, "eta") {
        Ok(e) => e as usize,
        Err(e) => return err_response(e),
    };
    let b = match get_input_bytes(req, "B") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };

    let expected_len = 64 * eta;
    if b.len() != expected_len {
        return err_response(format!(
            "SamplePolyCBD_{eta} expects {expected_len} bytes, got {}",
            b.len()
        ));
    }

    let f = sampling::sample_poly_cbd(&b, eta);
    let mut outputs = HashMap::new();
    outputs.insert("f".to_string(), hex::encode(poly_to_bytes(&f)));
    ok_outputs(outputs)
}

fn handle_sample_ntt(req: &Request) -> Response {
    let b = match get_input_bytes(req, "B") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };

    if b.len() != 34 {
        return err_response(format!("SampleNTT expects 34-byte seed, got {}", b.len()));
    }

    // Expand the seed via SHAKE128 to get XOF bytes, then rejection-sample.
    let mut hasher = Shake128::default();
    hasher.update(&b);
    let mut xof = hasher.finalize_xof();

    // We need enough bytes for rejection sampling. Worst case ~3*256*1.1
    let mut xof_bytes = vec![0u8; 3 * 256 * 2];
    xof.read(&mut xof_bytes);

    match sampling::sample_ntt_from_bytes(&xof_bytes) {
        Ok(a_hat) => {
            let mut outputs = HashMap::new();
            outputs.insert("a_hat".to_string(), hex::encode(poly_to_bytes(&a_hat)));
            ok_outputs(outputs)
        }
        Err(e) => err_response(e.to_string()),
    }
}

fn handle_ml_kem_keygen(req: &Request) -> Response {
    let randomness = match get_input_bytes(req, "randomness") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };
    if randomness.len() != 64 {
        return err_response(format!("keygen requires 64 bytes randomness (d||z), got {}", randomness.len()));
    }
    let d: [u8; 32] = randomness[..32].try_into().unwrap();
    let z: [u8; 32] = randomness[32..].try_into().unwrap();

    let param_set = get_param(req, "param_set").unwrap_or(768);
    let p = match param_set {
        512 => &params::ML_KEM_512,
        768 => &params::ML_KEM_768,
        1024 => &params::ML_KEM_1024,
        _ => return err_response(format!("unsupported param_set: {param_set}")),
    };

    let kp = kpke::ml_kem_keygen_internal(&d, &z, p);
    let mut outputs = HashMap::new();
    outputs.insert("ek".to_string(), hex::encode(&kp.ek));
    outputs.insert("dk".to_string(), hex::encode(&kp.dk));
    ok_outputs(outputs)
}

fn handle_ml_kem_encaps(req: &Request) -> Response {
    let ek = match get_input_bytes(req, "ek") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };

    let param = params::ALL_PARAMS
        .iter()
        .find(|p| ek.len() == 384 * p.k + 32);

    let p = match param {
        Some(p) => p,
        None => {
            return err_response(format!(
                "invalid encapsulation key length: {} bytes",
                ek.len()
            ));
        }
    };

    // Modulus check.
    let ek_pke = &ek[..384 * p.k];
    if !encode::ek_modulus_check(ek_pke) {
        return err_response(
            "encapsulation key failed modulus check: \
             ByteEncode_12(ByteDecode_12(ek_PKE)) != ek_PKE"
                .into(),
        );
    }

    // Get the randomness (message m) for deterministic encapsulation.
    let m_bytes = match get_input_bytes(req, "randomness") {
        Ok(b) => b,
        Err(_) => {
            // No randomness provided — generate fresh.
            let mut buf = [0u8; 32];
            getrandom(&mut buf);
            buf.to_vec()
        }
    };
    if m_bytes.len() != 32 {
        return err_response(format!("encaps randomness must be 32 bytes, got {}", m_bytes.len()));
    }
    let m: [u8; 32] = m_bytes.try_into().unwrap();

    let (ct, ss) = kpke::ml_kem_encaps_internal(&ek, &m, p);
    let mut outputs = HashMap::new();
    outputs.insert("c".to_string(), hex::encode(&ct));
    outputs.insert("K".to_string(), hex::encode(&ss));
    ok_outputs(outputs)
}

fn handle_ml_kem_decaps(req: &Request) -> Response {
    let ct = match get_input_bytes(req, "c") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };
    let dk = match get_input_bytes(req, "dk") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };

    // Determine parameter set from dk length.
    let param = params::ALL_PARAMS
        .iter()
        .find(|p| dk.len() == 768 * p.k + 96);

    let p = match param {
        Some(p) => p,
        None => {
            return err_response(format!(
                "invalid decapsulation key length: {} bytes",
                dk.len()
            ));
        }
    };

    // ML-KEM.Decaps_internal (Algorithm 18):
    // Parse dk = dk_PKE || ek || H(ek) || z
    let dk_pke_len = 384 * p.k;
    let ek_len = 384 * p.k + 32;
    let dk_pke = &dk[..dk_pke_len];
    let ek = &dk[dk_pke_len..dk_pke_len + ek_len];
    let _h_ek = &dk[dk_pke_len + ek_len..dk_pke_len + ek_len + 32];
    let z = &dk[dk_pke_len + ek_len + 32..dk_pke_len + ek_len + 64];

    // Decrypt: m' = K-PKE.Decrypt(dk_PKE, c)
    let m_prime = kpke::kpke_decrypt(dk_pke, &ct, p);

    // (K_bar, r) = G(m' || H(ek))
    let h_ek = sha3_256(ek);
    let mut g_input = Vec::with_capacity(64);
    g_input.extend_from_slice(&m_prime);
    g_input.extend_from_slice(&h_ek);
    let g_output = sha3_512(&g_input);
    let k_bar: [u8; 32] = g_output[..32].try_into().unwrap();
    let r: [u8; 32] = g_output[32..64].try_into().unwrap();

    // Re-encrypt: c' = K-PKE.Encrypt(ek, m', r)
    let c_prime = kpke::kpke_encrypt(ek, &m_prime, &r, p);

    // Implicit rejection: K = J(z || c)
    let mut j_input = Vec::new();
    j_input.extend_from_slice(z);
    j_input.extend_from_slice(&ct);
    let k_reject = shake256_32(&j_input);

    // Constant-time select: if c == c' then K_bar else K_reject
    let ct_eq = constant_time_eq(&ct, &c_prime);
    let mut k = [0u8; 32];
    for i in 0..32 {
        k[i] = (ct_eq & k_bar[i]) | (!ct_eq & k_reject[i]);
    }

    let mut outputs = HashMap::new();
    outputs.insert("K".to_string(), hex::encode(&k));
    ok_outputs(outputs)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() { return 0; }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    // Returns 0xFF if equal, 0x00 if not.
    let is_zero = diff as u16;
    ((is_zero.wrapping_sub(1)) >> 8) as u8
}

fn getrandom(buf: &mut [u8]) {
    use std::fs::File;
    use std::io::Read;
    let mut f = File::open("/dev/urandom").expect("open /dev/urandom");
    f.read_exact(buf).expect("read randomness");
}

fn sha3_256(data: &[u8]) -> [u8; 32] {
    use sha3::{Sha3_256, Digest};
    let mut h = Sha3_256::new();
    Digest::update(&mut h, data);
    h.finalize().into()
}

fn sha3_512(data: &[u8]) -> [u8; 64] {
    use sha3::{Sha3_512, Digest};
    let mut h = Sha3_512::new();
    Digest::update(&mut h, data);
    h.finalize().into()
}

fn shake256_32(data: &[u8]) -> [u8; 32] {
    use sha3::Shake256;
    let mut h = Shake256::default();
    h.update(data);
    let mut xof = h.finalize_xof();
    let mut out = [0u8; 32];
    xof.read(&mut out);
    out
}
