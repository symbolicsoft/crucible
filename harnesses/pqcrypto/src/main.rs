use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::panic;

use pqcrypto_traits::kem::{
    Ciphertext as CiphertextTrait, PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait,
    SharedSecret as SharedSecretTrait,
};
use serde::{Deserialize, Serialize};

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
    #[serde(skip_serializing_if = "is_false")]
    unsupported: bool,
}

fn is_false(b: &bool) -> bool {
    !b
}

#[derive(Serialize)]
struct Handshake {
    implementation: String,
    functions: Vec<String>,
}

fn ok_resp(outputs: HashMap<String, String>) -> Response {
    Response {
        outputs: Some(outputs),
        error: None,
        unsupported: false,
    }
}

fn err_resp(msg: String) -> Response {
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

fn get_input_bytes(inputs: &HashMap<String, String>, key: &str) -> Result<Vec<u8>, String> {
    let hex_str = inputs
        .get(key)
        .ok_or_else(|| format!("missing input '{}'", key))?;
    hex::decode(hex_str).map_err(|e| format!("invalid hex for '{}': {}", key, e))
}

fn get_param(params: &HashMap<String, i64>, key: &str) -> Result<i64, String> {
    params
        .get(key)
        .copied()
        .ok_or_else(|| format!("missing param '{}'", key))
}

fn handle_keygen(req: &Request) -> Response {
    let param_set = match get_param(&req.params, "param_set") {
        Ok(v) => v,
        Err(_) => 768, // default
    };

    match param_set {
        512 => {
            let (pk, sk) = pqcrypto_mlkem::mlkem512::keypair();
            let mut outputs = HashMap::new();
            outputs.insert("ek".to_string(), hex::encode(pk.as_bytes()));
            outputs.insert("dk".to_string(), hex::encode(sk.as_bytes()));
            ok_resp(outputs)
        }
        768 => {
            let (pk, sk) = pqcrypto_mlkem::mlkem768::keypair();
            let mut outputs = HashMap::new();
            outputs.insert("ek".to_string(), hex::encode(pk.as_bytes()));
            outputs.insert("dk".to_string(), hex::encode(sk.as_bytes()));
            ok_resp(outputs)
        }
        1024 => {
            let (pk, sk) = pqcrypto_mlkem::mlkem1024::keypair();
            let mut outputs = HashMap::new();
            outputs.insert("ek".to_string(), hex::encode(pk.as_bytes()));
            outputs.insert("dk".to_string(), hex::encode(sk.as_bytes()));
            ok_resp(outputs)
        }
        _ => err_resp(format!("unsupported param_set: {}", param_set)),
    }
}

fn handle_encaps(req: &Request) -> Response {
    let ek_bytes = match get_input_bytes(&req.inputs, "ek") {
        Ok(v) => v,
        Err(e) => return err_resp(e),
    };

    // Determine param set from ek length.
    // ML-KEM-512: 800 bytes, ML-KEM-768: 1184 bytes, ML-KEM-1024: 1568 bytes
    match ek_bytes.len() {
        800 => {
            let pk = match pqcrypto_mlkem::mlkem512::PublicKey::from_bytes(&ek_bytes) {
                Ok(pk) => pk,
                Err(e) => return err_resp(format!("invalid public key: {}", e)),
            };
            let (ss, ct) = pqcrypto_mlkem::mlkem512::encapsulate(&pk);
            let mut outputs = HashMap::new();
            outputs.insert("c".to_string(), hex::encode(ct.as_bytes()));
            outputs.insert("K".to_string(), hex::encode(ss.as_bytes()));
            ok_resp(outputs)
        }
        1184 => {
            let pk = match pqcrypto_mlkem::mlkem768::PublicKey::from_bytes(&ek_bytes) {
                Ok(pk) => pk,
                Err(e) => return err_resp(format!("invalid public key: {}", e)),
            };
            let (ss, ct) = pqcrypto_mlkem::mlkem768::encapsulate(&pk);
            let mut outputs = HashMap::new();
            outputs.insert("c".to_string(), hex::encode(ct.as_bytes()));
            outputs.insert("K".to_string(), hex::encode(ss.as_bytes()));
            ok_resp(outputs)
        }
        1568 => {
            let pk = match pqcrypto_mlkem::mlkem1024::PublicKey::from_bytes(&ek_bytes) {
                Ok(pk) => pk,
                Err(e) => return err_resp(format!("invalid public key: {}", e)),
            };
            let (ss, ct) = pqcrypto_mlkem::mlkem1024::encapsulate(&pk);
            let mut outputs = HashMap::new();
            outputs.insert("c".to_string(), hex::encode(ct.as_bytes()));
            outputs.insert("K".to_string(), hex::encode(ss.as_bytes()));
            ok_resp(outputs)
        }
        _ => err_resp(format!(
            "invalid encapsulation key length: {} bytes",
            ek_bytes.len()
        )),
    }
}

fn handle_decaps(req: &Request) -> Response {
    let c_bytes = match get_input_bytes(&req.inputs, "c") {
        Ok(v) => v,
        Err(e) => return err_resp(e),
    };
    let dk_bytes = match get_input_bytes(&req.inputs, "dk") {
        Ok(v) => v,
        Err(e) => return err_resp(e),
    };

    // Determine param set from dk (secret key) length.
    // ML-KEM-512: sk=1632, ct=768
    // ML-KEM-768: sk=2400, ct=1088
    // ML-KEM-1024: sk=3168, ct=1568
    match dk_bytes.len() {
        1632 => {
            let sk = match pqcrypto_mlkem::mlkem512::SecretKey::from_bytes(&dk_bytes) {
                Ok(sk) => sk,
                Err(e) => return err_resp(format!("invalid secret key: {}", e)),
            };
            let ct = match pqcrypto_mlkem::mlkem512::Ciphertext::from_bytes(&c_bytes) {
                Ok(ct) => ct,
                Err(e) => return err_resp(format!("invalid ciphertext: {}", e)),
            };
            let ss = pqcrypto_mlkem::mlkem512::decapsulate(&ct, &sk);
            let mut outputs = HashMap::new();
            outputs.insert("K".to_string(), hex::encode(ss.as_bytes()));
            ok_resp(outputs)
        }
        2400 => {
            let sk = match pqcrypto_mlkem::mlkem768::SecretKey::from_bytes(&dk_bytes) {
                Ok(sk) => sk,
                Err(e) => return err_resp(format!("invalid secret key: {}", e)),
            };
            let ct = match pqcrypto_mlkem::mlkem768::Ciphertext::from_bytes(&c_bytes) {
                Ok(ct) => ct,
                Err(e) => return err_resp(format!("invalid ciphertext: {}", e)),
            };
            let ss = pqcrypto_mlkem::mlkem768::decapsulate(&ct, &sk);
            let mut outputs = HashMap::new();
            outputs.insert("K".to_string(), hex::encode(ss.as_bytes()));
            ok_resp(outputs)
        }
        3168 => {
            let sk = match pqcrypto_mlkem::mlkem1024::SecretKey::from_bytes(&dk_bytes) {
                Ok(sk) => sk,
                Err(e) => return err_resp(format!("invalid secret key: {}", e)),
            };
            let ct = match pqcrypto_mlkem::mlkem1024::Ciphertext::from_bytes(&c_bytes) {
                Ok(ct) => ct,
                Err(e) => return err_resp(format!("invalid ciphertext: {}", e)),
            };
            let ss = pqcrypto_mlkem::mlkem1024::decapsulate(&ct, &sk);
            let mut outputs = HashMap::new();
            outputs.insert("K".to_string(), hex::encode(ss.as_bytes()));
            ok_resp(outputs)
        }
        _ => err_resp(format!(
            "invalid decapsulation key length: {} bytes",
            dk_bytes.len()
        )),
    }
}

fn handle_request(req: &Request) -> Response {
    match req.function.as_str() {
        "ML_KEM_KeyGen" => handle_keygen(req),
        "ML_KEM_Encaps" => handle_encaps(req),
        "ML_KEM_Decaps" => handle_decaps(req),
        _ => unsupported_resp(),
    }
}

fn handle_request_safe(req: &Request) -> Response {
    match panic::catch_unwind(panic::AssertUnwindSafe(|| handle_request(req))) {
        Ok(resp) => resp,
        Err(e) => {
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            err_resp(format!("panic: {}", msg))
        }
    }
}

fn main() {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    // Send handshake.
    let handshake = Handshake {
        implementation: "pqcrypto-mlkem".to_string(),
        functions: vec![
            "ML_KEM_KeyGen".to_string(),
            "ML_KEM_Encaps".to_string(),
            "ML_KEM_Decaps".to_string(),
        ],
    };
    serde_json::to_writer(&mut out, &handshake).unwrap();
    out.write_all(b"\n").unwrap();
    out.flush().unwrap();

    // Process requests line by line.
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.is_empty() {
            break;
        }

        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = err_resp(format!("invalid JSON: {}", e));
                serde_json::to_writer(&mut out, &resp).unwrap();
                out.write_all(b"\n").unwrap();
                out.flush().unwrap();
                continue;
            }
        };

        let resp = handle_request_safe(&req);
        serde_json::to_writer(&mut out, &resp).unwrap();
        out.write_all(b"\n").unwrap();
        out.flush().unwrap();
    }
}
