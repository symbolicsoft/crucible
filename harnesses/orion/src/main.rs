use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};

use orion::hazardous::kem::mlkem512 as orion_mlkem512;
use orion::hazardous::kem::mlkem768 as orion_mlkem768;
use orion::hazardous::kem::mlkem1024 as orion_mlkem1024;

use orion::hazardous::dsa::mldsa44 as orion_mldsa44;
use orion::hazardous::dsa::mldsa65 as orion_mldsa65;
use orion::hazardous::dsa::mldsa87 as orion_mldsa87;

use orion::KP;

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

// ---- Helpers ----

fn get_input_bytes(req: &Request, key: &str) -> Result<Vec<u8>, String> {
    let hex_str = req
        .inputs
        .get(key)
        .ok_or_else(|| format!("missing input '{key}'"))?;
    hex::decode(hex_str).map_err(|e| format!("invalid hex in input '{key}': {e}"))
}

fn get_param(params: &HashMap<String, i64>, key: &str) -> Result<i64, String> {
    params
        .get(key)
        .copied()
        .ok_or_else(|| format!("missing param '{}'", key))
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

fn handle_kem_keygen(req: &Request) -> Response {
    let seed = match get_input_bytes(req, "randomness") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };
    if seed.len() != 64 {
        return err_response("seed requires 64 bytes".into());
    }

    let param_set = get_param(&req.params, "param_set").unwrap_or(768);

    match param_set {
        512 => {
            let seed = orion_mlkem512::Seed::try_from(&seed).unwrap();
            let kp = orion_mlkem512::KeyPair::new(seed).unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("ek".to_string(), hex::encode(kp.public().as_ref()));
            outputs.insert(
                "dk".to_string(),
                hex::encode(kp.private().unprotected_as_ref()),
            );
            ok_response(outputs)
        }
        768 => {
            let seed = orion_mlkem768::Seed::try_from(&seed).unwrap();
            let kp = orion_mlkem768::KeyPair::new(seed).unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("ek".to_string(), hex::encode(kp.public().as_ref()));
            outputs.insert(
                "dk".to_string(),
                hex::encode(kp.private().unprotected_as_ref()),
            );
            ok_response(outputs)
        }
        1024 => {
            let seed = orion_mlkem1024::Seed::try_from(&seed).unwrap();
            let kp = orion_mlkem1024::KeyPair::new(seed).unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("ek".to_string(), hex::encode(kp.public().as_ref()));
            outputs.insert(
                "dk".to_string(),
                hex::encode(kp.private().unprotected_as_ref()),
            );
            ok_response(outputs)
        }
        _ => err_response(format!("unsupported param_set: {}", param_set)),
    }
}

fn handle_kem_encaps(req: &Request) -> Response {
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
            let pk = match orion_mlkem512::EncapsulationKey::try_from(&ek_bytes) {
                Ok(pk) => pk,
                Err(e) => return err_response(format!("invalid public key: {}", e)),
            };
            // SAFETY: unwrap() should never panic as we have const-length on `rnd`.
            let (ss, ct) = pk
                .encap_deterministic(&orion_mlkem512::ExplicitRandom::from(rnd))
                .unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("c".to_string(), hex::encode(ct.as_ref()));
            outputs.insert("K".to_string(), hex::encode(ss.unprotected_as_ref()));
            ok_response(outputs)
        }
        1184 => {
            let pk = match orion_mlkem768::EncapsulationKey::try_from(&ek_bytes) {
                Ok(pk) => pk,
                Err(e) => return err_response(format!("invalid public key: {}", e)),
            };
            // SAFETY: unwrap() should never panic as we have const-length on `rnd`.
            let (ss, ct) = pk
                .encap_deterministic(&orion_mlkem768::ExplicitRandom::from(rnd))
                .unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("c".to_string(), hex::encode(ct.as_ref()));
            outputs.insert("K".to_string(), hex::encode(ss.unprotected_as_ref()));
            ok_response(outputs)
        }
        1568 => {
            let pk = match orion_mlkem1024::EncapsulationKey::try_from(&ek_bytes) {
                Ok(pk) => pk,
                Err(e) => return err_response(format!("invalid public key: {}", e)),
            };
            // SAFETY: unwrap() should never panic as we have const-length on `rnd`.
            let (ss, ct) = pk
                .encap_deterministic(&orion_mlkem1024::ExplicitRandom::from(rnd))
                .unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("c".to_string(), hex::encode(ct.as_ref()));
            outputs.insert("K".to_string(), hex::encode(ss.unprotected_as_ref()));
            ok_response(outputs)
        }
        _ => err_response(format!(
            "invalid encapsulation key length: {} bytes",
            ek_bytes.len()
        )),
    }
}

fn handle_kem_decaps(req: &Request) -> Response {
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
            let ct = match orion_mlkem512::Ciphertext::try_from(ct_bytes.as_slice()) {
                Ok(ct) => ct,
                Err(_e) => {
                    return err_response(format!(
                        "invalid ciphertext length for 512: {}",
                        ct_bytes.len()
                    ));
                }
            };

            // SAFETY: Should not panic under normal circumstances for these tests.
            let ss = sk.decap(&ct).unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("K".to_string(), hex::encode(ss.unprotected_as_ref()));
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
            let ct = match orion_mlkem768::Ciphertext::try_from(ct_bytes.as_slice()) {
                Ok(ct) => ct,
                Err(_e) => {
                    return err_response(format!(
                        "invalid ciphertext length for 512: {}",
                        ct_bytes.len()
                    ));
                }
            };

            // SAFETY: Should not panic under normal circumstances for these tests.
            let ss = sk.decap(&ct).unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("K".to_string(), hex::encode(ss.unprotected_as_ref()));
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
            let ct = match orion_mlkem1024::Ciphertext::try_from(ct_bytes.as_slice()) {
                Ok(ct) => ct,
                Err(_e) => {
                    return err_response(format!(
                        "invalid ciphertext length for 512: {}",
                        ct_bytes.len()
                    ));
                }
            };

            // SAFETY: Should not panic under normal circumstances for these tests.
            let ss = sk.decap(&ct).unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("K".to_string(), hex::encode(ss.unprotected_as_ref()));
            ok_response(outputs)
        }
        _ => err_response(format!(
            "invalid decapsulation key length: {} bytes",
            dk_bytes.len()
        )),
    }
}

fn handle_kem_validate_pk(req: &Request) -> Response {
    let pk_bytes = match get_input_bytes(req, "ek") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };

    let valid = match pk_bytes.len() {
        800 => orion_mlkem512::EncapsulationKey::try_from(pk_bytes.as_slice()).is_ok(),
        1184 => orion_mlkem768::EncapsulationKey::try_from(pk_bytes.as_slice()).is_ok(),
        1568 => orion_mlkem1024::EncapsulationKey::try_from(pk_bytes.as_slice()).is_ok(),
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

fn handle_dsa_keygen(req: &Request) -> Response {
    let seed = match get_input_bytes(req, "seed") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };
    if seed.len() != 32 {
        return err_response("seed requires 32 bytes".into());
    }

    let param_set = get_param(&req.params, "param_set").unwrap_or(768);

    match param_set {
        44 => {
            let seed = orion_mldsa44::Seed::try_from(&seed).unwrap();
            let kp = orion_mldsa44::KeyPair::new(seed).unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("pk".to_string(), hex::encode(kp.public().as_ref()));
            outputs.insert(
                "sk".to_string(),
                hex::encode(kp.private().unprotected_as_ref()),
            );
            ok_response(outputs)
        }
        65 => {
            let seed = orion_mldsa65::Seed::try_from(&seed).unwrap();
            let kp = orion_mldsa65::KeyPair::new(seed).unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("pk".to_string(), hex::encode(kp.public().as_ref()));
            outputs.insert(
                "sk".to_string(),
                hex::encode(kp.private().unprotected_as_ref()),
            );
            ok_response(outputs)
        }
        87 => {
            let seed = orion_mldsa87::Seed::try_from(&seed).unwrap();
            let kp = orion_mldsa87::KeyPair::new(seed).unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("pk".to_string(), hex::encode(kp.public().as_ref()));
            outputs.insert(
                "sk".to_string(),
                hex::encode(kp.private().unprotected_as_ref()),
            );
            ok_response(outputs)
        }
        _ => err_response("unsupported param_set".into()),
    }
}

fn handle_dsa_sign(req: &Request) -> Response {
    let sk = match get_input_bytes(req, "sk") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };
    let msg = match get_input_bytes(req, "message") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };
    let rnd = match get_input_bytes(req, "rnd") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };

    match sk.len() {
        orion_mldsa44::SIGNING_KEY_SIZE => {
            let sk = match orion_mldsa44::SigningKey::try_from(sk.as_slice()) {
                Ok(sk) => sk,
                Err(_e) => {
                    return err_response("invalid private key".to_string());
                }
            };
            let rnd = match orion_mldsa44::ExplicitRandom::try_from(rnd.as_slice()) {
                Ok(rnd) => rnd,
                Err(_e) => {
                    return err_response("invalid rnd".to_string());
                }
            };

            let sig = sk.sign_with_rnd(&msg, &[], &rnd).unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("signature".to_string(), hex::encode(sig.as_ref()));
            ok_response(outputs)
        }
        orion_mldsa65::SIGNING_KEY_SIZE => {
            let sk = match orion_mldsa65::SigningKey::try_from(sk.as_slice()) {
                Ok(sk) => sk,
                Err(_e) => {
                    return err_response("invalid private key".to_string());
                }
            };
            let rnd = match orion_mldsa65::ExplicitRandom::try_from(rnd.as_slice()) {
                Ok(rnd) => rnd,
                Err(_e) => {
                    return err_response("invalid rnd".to_string());
                }
            };

            let sig = sk.sign_with_rnd(&msg, &[], &rnd).unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("signature".to_string(), hex::encode(sig.as_ref()));
            ok_response(outputs)
        }
        orion_mldsa87::SIGNING_KEY_SIZE => {
            let sk = match orion_mldsa87::SigningKey::try_from(sk.as_slice()) {
                Ok(sk) => sk,
                Err(_e) => {
                    return err_response("invalid private key".to_string());
                }
            };
            let rnd = match orion_mldsa87::ExplicitRandom::try_from(rnd.as_slice()) {
                Ok(rnd) => rnd,
                Err(_e) => {
                    return err_response("invalid rnd".to_string());
                }
            };

            let sig = sk.sign_with_rnd(&msg, &[], &rnd).unwrap();
            let mut outputs = HashMap::new();
            outputs.insert("signature".to_string(), hex::encode(sig.as_ref()));
            ok_response(outputs)
        }
        _ => err_response("unsupported param_set".into()),
    }
}

fn handle_dsa_verify(req: &Request) -> Response {
    let pk = match get_input_bytes(req, "pk") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };
    let msg = match get_input_bytes(req, "message") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };
    let sig = match get_input_bytes(req, "sigma") {
        Ok(b) => b,
        Err(e) => return err_response(e),
    };

    match pk.len() {
        orion_mldsa44::VERIFYING_KEY_SIZE => {
            let pk = match orion_mldsa44::VerifyingKey::try_from(pk.as_slice()) {
                Ok(pk) => pk,
                Err(_e) => {
                    return err_response("invalid private key".to_string());
                }
            };
            let sig = match orion_mldsa44::Signature::try_from(sig.as_slice()) {
                Ok(sig) => sig,
                Err(_e) => {
                    return err_response("invalid rnd".to_string());
                }
            };

            let mut outputs = HashMap::new();
            if let Ok(()) = pk.verify(&msg, &[], &sig) {
                outputs.insert("valid".to_string(), "01".into());
            } else {
                outputs.insert("valid".to_string(), "00".into());
            }

            ok_response(outputs)
        }
        orion_mldsa65::VERIFYING_KEY_SIZE => {
            let pk = match orion_mldsa65::VerifyingKey::try_from(pk.as_slice()) {
                Ok(pk) => pk,
                Err(_e) => {
                    return err_response("invalid private key".to_string());
                }
            };
            let sig = match orion_mldsa65::Signature::try_from(sig.as_slice()) {
                Ok(sig) => sig,
                Err(_e) => {
                    return err_response("invalid rnd".to_string());
                }
            };

            let mut outputs = HashMap::new();
            if let Ok(()) = pk.verify(&msg, &[], &sig) {
                outputs.insert("valid".to_string(), "01".into());
            } else {
                outputs.insert("valid".to_string(), "00".into());
            }

            ok_response(outputs)
        }
        orion_mldsa87::VERIFYING_KEY_SIZE => {
            let pk = match orion_mldsa87::VerifyingKey::try_from(pk.as_slice()) {
                Ok(pk) => pk,
                Err(_e) => {
                    return err_response("invalid private key".to_string());
                }
            };
            let sig = match orion_mldsa87::Signature::try_from(sig.as_slice()) {
                Ok(sig) => sig,
                Err(_e) => {
                    return err_response("invalid rnd".to_string());
                }
            };

            let mut outputs = HashMap::new();
            if let Ok(()) = pk.verify(&msg, &[], &sig) {
                outputs.insert("valid".to_string(), "01".into());
            } else {
                outputs.insert("valid".to_string(), "00".into());
            }

            ok_response(outputs)
        }
        _ => err_response("unsupported param_set".into()),
    }
}

fn main() {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let handshake = Handshake {
        implementation: "orion-0.18.0".to_string(),
        functions: vec![
            "ML_KEM_KeyGen".into(),
            "ML_KEM_Encaps".into(),
            "ML_KEM_Decaps".into(),
            "ML_KEM_ValidatePK".into(),
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
        "ML_KEM_KeyGen" => handle_kem_keygen(req),
        "ML_KEM_Encaps" => handle_kem_encaps(req),
        "ML_KEM_Decaps" => handle_kem_decaps(req),
        "ML_KEM_ValidatePK" => handle_kem_validate_pk(req),
        "ML_DSA_KeyGen" => handle_dsa_keygen(req),
        "ML_DSA_Sign" => handle_dsa_sign(req),
        "ML_DSA_Verify" => handle_dsa_verify(req),
        _ => unsupported_resp(),
    }
}
