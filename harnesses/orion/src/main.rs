use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};

use orion::hazardous::kem::mlkem512 as orion_mlkem512;
use orion::hazardous::kem::mlkem768 as orion_mlkem768;
use orion::hazardous::kem::mlkem1024 as orion_mlkem1024;

#[derive(Deserialize)]
struct Request {
    function: String,
    #[serde(default)]
    inputs: HashMap<String, String>,
    #[serde(default)]
    _params: HashMap<String, i64>,
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

// ---- Helpers ----

fn get_input_bytes(req: &Request, key: &str) -> Result<Vec<u8>, String> {
    let hex_str = req
        .inputs
        .get(key)
        .ok_or_else(|| format!("missing input '{key}'"))?;
    hex::decode(hex_str).map_err(|e| format!("invalid hex in input '{key}': {e}"))
}

fn ok_response(outputs: HashMap<String, String>) -> Response {
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

fn unsupported_resp() -> Response {
    Response {
        outputs: None,
        error: None,
        unsupported: true,
    }
}

// ---- Simple randomness ----

fn getrandom(buf: &mut [u8]) {
    use std::fs::File;
    use std::io::Read;
    let mut f = File::open("/dev/urandom").expect("failed to open /dev/urandom");
    f.read_exact(buf).expect("failed to read randomness");
}

// ---- Top-level ML-KEM operations via Orion ----

// Orion cannot at the time of writing support KeyGen test logic,
// as it relies on deterministically generating decapsulation key
// and interpreting as a raw byteslice, which the API does not
// currently allow.

fn handle_encaps(req: &Request) -> Response {
    let ek_bytes = match get_input_bytes(req, "ek") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };

    let randomness = match get_input_bytes(req, "randomness") {
        Ok(b) => b,
        Err(_) => {
            let mut rng = [0u8; 32];
            getrandom(&mut rng);
            rng.to_vec()
        }
    };

    if randomness.len() != 32 {
        return err_response(format!(
            "encapsulation randomness must be 32 bytes, got {}",
            randomness.len()
        ));
    }
    let mut rnd = [0u8; 32];
    rnd.copy_from_slice(&randomness);

    // Determine param set from ek length.
    // ML-KEM-512: 800 bytes, ML-KEM-768: 1184 bytes, ML-KEM-1024: 1568 bytes
    match ek_bytes.len() {
        800 => {
            let pk = match orion_mlkem512::EncapsulationKey::from_slice(&ek_bytes) {
                Ok(pk) => pk,
                Err(e) => return err_response(format!("invalid public key: {}", e)),
            };
            // SAFETY: unwrap() should never panic as we have const-length on `rnd`.
            let (ss, ct) = pk.encap_deterministic(&rnd).unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("c".to_string(), hex::encode(ct.as_ref()));
            outputs.insert("K".to_string(), hex::encode(ss.unprotected_as_bytes()));
            ok_response(outputs)
        }
        1184 => {
            let pk = match orion_mlkem768::EncapsulationKey::from_slice(&ek_bytes) {
                Ok(pk) => pk,
                Err(e) => return err_response(format!("invalid public key: {}", e)),
            };
            // SAFETY: unwrap() should never panic as we have const-length on `rnd`.
            let (ss, ct) = pk.encap_deterministic(&rnd).unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("c".to_string(), hex::encode(ct.as_ref()));
            outputs.insert("K".to_string(), hex::encode(ss.unprotected_as_bytes()));
            ok_response(outputs)
        }
        1568 => {
            let pk = match orion_mlkem1024::EncapsulationKey::from_slice(&ek_bytes) {
                Ok(pk) => pk,
                Err(e) => return err_response(format!("invalid public key: {}", e)),
            };
            // SAFETY: unwrap() should never panic as we have const-length on `rnd`.
            let (ss, ct) = pk.encap_deterministic(&rnd).unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("c".to_string(), hex::encode(ct.as_ref()));
            outputs.insert("K".to_string(), hex::encode(ss.unprotected_as_bytes()));
            ok_response(outputs)
        }
        _ => err_response(format!(
            "invalid encapsulation key length: {} bytes",
            ek_bytes.len()
        )),
    }
}

fn handle_decaps(req: &Request) -> Response {
    let ct_bytes = match get_input_bytes(req, "c") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };
    let dk_bytes = match get_input_bytes(req, "dk") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };

    // Determine parameter set from dk length.
    match dk_bytes.len() {
        1632 => {
            // ML-KEM-512: dk = 1632 bytes
            let sk =
                match orion_mlkem512::DecapsulationKey::unchecked_from_slice(dk_bytes.as_slice()) {
                    Ok(sk) => sk,
                    Err(_e) => {
                        return err_response(
                            "invalid decapsulation key re. FIPS-203, section 7.3".to_string(),
                        );
                    }
                };
            let ct = orion_mlkem512::Ciphertext::try_from(ct_bytes.as_slice())
                .map_err(|_| format!("invalid ciphertext length for 512: {}", ct_bytes.len()))
                .unwrap();

            // SAFETY: Should not panic under normal circumstances for these tests.
            let ss = sk.decap(&ct).unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("K".to_string(), hex::encode(ss.unprotected_as_bytes()));
            ok_response(outputs)
        }
        2400 => {
            // ML-KEM-768: dk = 2400 bytes
            let sk =
                match orion_mlkem768::DecapsulationKey::unchecked_from_slice(dk_bytes.as_slice()) {
                    Ok(sk) => sk,
                    Err(_e) => {
                        return err_response(
                            "invalid decapsulation key re. FIPS-203, section 7.3".to_string(),
                        );
                    }
                };
            let ct = orion_mlkem768::Ciphertext::try_from(ct_bytes.as_slice())
                .map_err(|_| format!("invalid ciphertext length for 768: {}", ct_bytes.len()))
                .unwrap();

            // SAFETY: Should not panic under normal circumstances for these tests.
            let ss = sk.decap(&ct).unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("K".to_string(), hex::encode(ss.unprotected_as_bytes()));
            ok_response(outputs)
        }
        3168 => {
            // ML-KEM-1024: dk = 3168 bytes
            let sk = match orion_mlkem1024::DecapsulationKey::unchecked_from_slice(
                dk_bytes.as_slice(),
            ) {
                Ok(sk) => sk,
                Err(_e) => {
                    return err_response(
                        "invalid decapsulation key re. FIPS-203, section 7.3".to_string(),
                    );
                }
            };
            let ct = orion_mlkem1024::Ciphertext::try_from(ct_bytes.as_slice())
                .map_err(|_| format!("invalid ciphertext length for 1024: {}", ct_bytes.len()))
                .unwrap();

            // SAFETY: Should not panic under normal circumstances for these tests.
            let ss = sk.decap(&ct).unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("K".to_string(), hex::encode(ss.unprotected_as_bytes()));
            ok_response(outputs)
        }
        _ => err_response(format!(
            "invalid decapsulation key length: {} bytes",
            dk_bytes.len()
        )),
    }
}

fn handle_validate_pk(req: &Request) -> Response {
    let pk_bytes = match get_input_bytes(req, "ek") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };

    let valid = match pk_bytes.len() {
        800 => orion_mlkem512::EncapsulationKey::from_slice(pk_bytes.as_slice()).is_ok(),
        1184 => orion_mlkem768::EncapsulationKey::from_slice(pk_bytes.as_slice()).is_ok(),
        1568 => orion_mlkem1024::EncapsulationKey::from_slice(pk_bytes.as_slice()).is_ok(),
        _ => {
            return err_response(format!(
                "invalid public key length: {} bytes",
                pk_bytes.len()
            ));
        }
    };

    let mut outputs = HashMap::new();
    outputs.insert("valid".to_string(), if valid { "01" } else { "00" }.into());
    ok_response(outputs)
}

fn main() {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let handshake = Handshake {
        implementation: "orion-mlkem-0.17.13".to_string(),
        functions: vec![
            "ML_KEM_Encaps".into(),
            "ML_KEM_Decaps".into(),
            "ML_KEM_ValidatePK".into(),
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
                writeln!(
                    out,
                    "{}",
                    serde_json::to_string(&Response {
                        outputs: None,
                        error: Some(msg),
                        unsupported: false,
                    })
                    .unwrap()
                )
                .unwrap();
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
        "ML_KEM_Encaps" => handle_encaps(req),
        "ML_KEM_Decaps" => handle_decaps(req),
        "ML_KEM_ValidatePK" => handle_validate_pk(req),
        _ => unsupported_resp(),
    }
}
