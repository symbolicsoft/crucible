//! K-PKE and ML-KEM internal algorithms per FIPS 203 §5–§6.
//! Used by Crucible to compute expected outputs for black-box testing.

use super::compress::{compress_d, decompress_d};
use super::encode::{byte_decode, byte_encode};
use super::ntt::{inv_ntt, multiply_ntts, ntt};
use super::sampling::{sample_ntt_from_bytes, sample_poly_cbd};
use crate::params::{MlKemParams, N, Q};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512, Shake128, Shake256};

/// Result of K-PKE.KeyGen (Algorithm 13).
pub struct KpkeKeyPair {
    /// Encryption key: ByteEncode_12(t_hat) || rho
    pub ek: Vec<u8>,
    /// Decryption key: ByteEncode_12(s_hat)
    pub dk: Vec<u8>,
}

/// Result of ML-KEM.KeyGen_internal (Algorithm 16).
pub struct MlKemKeyPair {
    /// Encapsulation key: ek_PKE || H(ek)... actually just ek_PKE for the public portion.
    pub ek: Vec<u8>,
    /// Decapsulation key: dk_PKE || ek || H(ek) || z
    pub dk: Vec<u8>,
}

/// K-PKE.KeyGen (Algorithm 13).
/// Input: 32-byte seed d.
/// Output: encryption key ek_PKE and decryption key dk_PKE.
pub fn kpke_keygen(d: &[u8; 32], params: &MlKemParams) -> KpkeKeyPair {
    let k = params.k;
    let eta1 = params.eta1;

    // Line 1: (rho, sigma) = G(d || k)
    let mut g_input = Vec::with_capacity(33);
    g_input.extend_from_slice(d);
    g_input.push(k as u8);
    let g_output = sha3_512(&g_input);
    let rho = &g_output[..32];
    let sigma = &g_output[32..64];

    // Lines 3-7: Generate matrix A_hat from rho via SampleNTT.
    let a_hat = gen_matrix(rho, k);

    // Lines 8-10: Generate secret vector s from sigma via CBD.
    let mut s = Vec::with_capacity(k);
    for i in 0..k {
        let prf_output = prf(eta1, sigma, i as u8);
        s.push(sample_poly_cbd(&prf_output, eta1));
    }

    // Lines 11-13: Generate error vector e from sigma via CBD.
    let mut e = Vec::with_capacity(k);
    for i in 0..k {
        let prf_output = prf(eta1, sigma, (k + i) as u8);
        e.push(sample_poly_cbd(&prf_output, eta1));
    }

    // Line 9: s_hat = NTT(s)
    let s_hat: Vec<[u32; N]> = s.iter().map(|si| ntt(si)).collect();

    // Line 10: e_hat = NTT(e)
    let e_hat: Vec<[u32; N]> = e.iter().map(|ei| ntt(ei)).collect();

    // Line 11: t_hat = A_hat ∘ s_hat + e_hat
    let mut t_hat = vec![[0u32; N]; k];
    for i in 0..k {
        for j in 0..k {
            let prod = multiply_ntts(&a_hat[i][j], &s_hat[j]);
            for c in 0..N {
                t_hat[i][c] = (t_hat[i][c] + prod[c]) % Q;
            }
        }
        for c in 0..N {
            t_hat[i][c] = (t_hat[i][c] + e_hat[i][c]) % Q;
        }
    }

    // Line 12: ek_PKE = ByteEncode_12(t_hat) || rho
    let mut ek = Vec::with_capacity(384 * k + 32);
    for i in 0..k {
        ek.extend_from_slice(&byte_encode(&t_hat[i], 12));
    }
    ek.extend_from_slice(rho);

    // Line 13: dk_PKE = ByteEncode_12(s_hat)
    let mut dk = Vec::with_capacity(384 * k);
    for i in 0..k {
        dk.extend_from_slice(&byte_encode(&s_hat[i], 12));
    }

    KpkeKeyPair { ek, dk }
}

/// K-PKE.Encrypt (Algorithm 14).
/// Input: encryption key ek_PKE, 32-byte message m, 32-byte randomness r.
pub fn kpke_encrypt(ek_pke: &[u8], m: &[u8; 32], r: &[u8; 32], params: &MlKemParams) -> Vec<u8> {
    let k = params.k;
    let eta1 = params.eta1;
    let eta2 = params.eta2;
    let du = params.du;
    let dv = params.dv;

    // Line 2: t_hat = ByteDecode_12(ek_PKE[0:384k])
    let mut t_hat = Vec::with_capacity(k);
    for i in 0..k {
        let chunk = &ek_pke[384 * i..384 * (i + 1)];
        t_hat.push(byte_decode(chunk, 12));
    }

    // Line 3: rho = ek_PKE[384k:]
    let rho = &ek_pke[384 * k..384 * k + 32];

    // Lines 4-8: Generate matrix A_hat from rho.
    let a_hat = gen_matrix(rho, k);

    // Lines 9-11: Generate r vector from randomness.
    let mut r_vec = Vec::with_capacity(k);
    for i in 0..k {
        let prf_output = prf(eta1, r, i as u8);
        r_vec.push(sample_poly_cbd(&prf_output, eta1));
    }

    // Lines 12-14: Generate e1 error vector.
    let mut e1 = Vec::with_capacity(k);
    for i in 0..k {
        let prf_output = prf(eta2, r, (k + i) as u8);
        e1.push(sample_poly_cbd(&prf_output, eta2));
    }

    // Line 15: e2 = SamplePolyCBD_eta2(PRF(r, 2k))
    let prf_output = prf(eta2, r, (2 * k) as u8);
    let e2 = sample_poly_cbd(&prf_output, eta2);

    // Line 16: r_hat = NTT(r_vec)
    let r_hat: Vec<[u32; N]> = r_vec.iter().map(|ri| ntt(ri)).collect();

    // Line 17: u = NTT_inv(A_hat^T ∘ r_hat) + e1
    let mut u = vec![[0u32; N]; k];
    for i in 0..k {
        let mut acc = [0u32; N];
        for j in 0..k {
            let prod = multiply_ntts(&a_hat[j][i], &r_hat[j]); // A_hat^T
            for c in 0..N {
                acc[c] = (acc[c] + prod[c]) % Q;
            }
        }
        let u_i = inv_ntt(&acc);
        for c in 0..N {
            u[i][c] = (u_i[c] + e1[i][c]) % Q;
        }
    }

    // Line 18: mu = Decompress_1(ByteDecode_1(m))
    let m_decoded = byte_decode(m, 1);
    let mut mu = [0u32; N];
    for c in 0..N {
        mu[c] = decompress_d(m_decoded[c], 1);
    }

    // Line 19: v = NTT_inv(t_hat^T ∘ r_hat) + e2 + mu
    let mut v_acc = [0u32; N];
    for j in 0..k {
        let prod = multiply_ntts(&t_hat[j], &r_hat[j]);
        for c in 0..N {
            v_acc[c] = (v_acc[c] + prod[c]) % Q;
        }
    }
    let v_base = inv_ntt(&v_acc);
    let mut v = [0u32; N];
    for c in 0..N {
        v[c] = (v_base[c] + e2[c] + mu[c]) % Q;
    }

    // Lines 20-21: c1 = ByteEncode_du(Compress_du(u)), c2 = ByteEncode_dv(Compress_dv(v))
    let mut ciphertext = Vec::new();
    for i in 0..k {
        let mut compressed = [0u32; N];
        for c in 0..N {
            compressed[c] = compress_d(u[i][c], du as u32);
        }
        ciphertext.extend_from_slice(&byte_encode(&compressed, du as u32));
    }
    let mut v_compressed = [0u32; N];
    for c in 0..N {
        v_compressed[c] = compress_d(v[c], dv as u32);
    }
    ciphertext.extend_from_slice(&byte_encode(&v_compressed, dv as u32));

    ciphertext
}

/// K-PKE.Decrypt (Algorithm 15).
/// Input: decryption key dk_PKE, ciphertext c.
/// Output: 32-byte message m.
pub fn kpke_decrypt(dk_pke: &[u8], c: &[u8], params: &MlKemParams) -> [u8; 32] {
    let k = params.k;
    let du = params.du;
    let dv = params.dv;

    // Parse ciphertext: c1 (compressed u) and c2 (compressed v).
    let c1_len = 32 * du * k;
    let c1 = &c[..c1_len];
    let c2 = &c[c1_len..];

    // Decompress u: ByteDecode_du then Decompress_du.
    let mut u = Vec::with_capacity(k);
    for i in 0..k {
        let chunk = &c1[32 * du * i..32 * du * (i + 1)];
        let decoded = byte_decode(chunk, du as u32);
        let mut decompressed = [0u32; N];
        for c in 0..N {
            decompressed[c] = decompress_d(decoded[c], du as u32);
        }
        u.push(decompressed);
    }

    // Decompress v: ByteDecode_dv then Decompress_dv.
    let v_decoded = byte_decode(c2, dv as u32);
    let mut v = [0u32; N];
    for c in 0..N {
        v[c] = decompress_d(v_decoded[c], dv as u32);
    }

    // Parse dk_PKE: s_hat = ByteDecode_12(dk_PKE).
    let mut s_hat = Vec::with_capacity(k);
    for i in 0..k {
        let chunk = &dk_pke[384 * i..384 * (i + 1)];
        s_hat.push(byte_decode(chunk, 12));
    }

    // w = NTT_inv(s_hat^T ∘ NTT(u))
    let u_hat: Vec<[u32; N]> = u.iter().map(|ui| ntt(ui)).collect();
    let mut w_acc = [0u32; N];
    for j in 0..k {
        let prod = multiply_ntts(&s_hat[j], &u_hat[j]);
        for c in 0..N {
            w_acc[c] = (w_acc[c] + prod[c]) % Q;
        }
    }
    let w = inv_ntt(&w_acc);

    // m = ByteEncode_1(Compress_1(v - w))
    let mut diff = [0u32; N];
    for c in 0..N {
        diff[c] = (v[c] + Q - w[c]) % Q;
    }
    let mut compressed = [0u32; N];
    for c in 0..N {
        compressed[c] = compress_d(diff[c], 1);
    }
    let m_bytes = byte_encode(&compressed, 1);

    let mut m = [0u8; 32];
    m.copy_from_slice(&m_bytes);
    m
}

/// ML-KEM.KeyGen_internal (Algorithm 16).
/// Input: 32-byte seed d, 32-byte seed z.
pub fn ml_kem_keygen_internal(d: &[u8; 32], z: &[u8; 32], params: &MlKemParams) -> MlKemKeyPair {
    let kpke = kpke_keygen(d, params);
    let ek = kpke.ek.clone();
    let h_ek = sha3_256(&ek);

    // dk = dk_PKE || ek || H(ek) || z
    let mut dk = Vec::new();
    dk.extend_from_slice(&kpke.dk);
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&h_ek);
    dk.extend_from_slice(z);

    MlKemKeyPair { ek, dk }
}

/// ML-KEM.Encaps_internal (Algorithm 17).
/// Input: encapsulation key ek, 32-byte random message m.
/// Output: (ciphertext, shared_secret).
pub fn ml_kem_encaps_internal(
    ek: &[u8],
    m: &[u8; 32],
    params: &MlKemParams,
) -> (Vec<u8>, [u8; 32]) {
    let h_ek = sha3_256(ek);

    // (K, r) = G(m || H(ek))
    let mut g_input = Vec::with_capacity(64);
    g_input.extend_from_slice(m);
    g_input.extend_from_slice(&h_ek);
    let g_output = sha3_512(&g_input);
    let shared_secret: [u8; 32] = g_output[..32].try_into().unwrap();
    let r: [u8; 32] = g_output[32..64].try_into().unwrap();

    let ciphertext = kpke_encrypt(ek, m, &r, params);

    (ciphertext, shared_secret)
}

// ---- Internal helpers ----

/// Generate matrix A_hat from seed rho using SampleNTT (Algorithm 7).
fn gen_matrix(rho: &[u8], k: usize) -> Vec<Vec<[u32; N]>> {
    let mut a_hat = vec![vec![[0u32; N]; k]; k];
    for i in 0..k {
        for j in 0..k {
            let mut seed = Vec::with_capacity(34);
            seed.extend_from_slice(rho);
            seed.push(j as u8);
            seed.push(i as u8);

            // Expand seed via SHAKE128.
            let mut hasher = Shake128::default();
            hasher.update(&seed);
            let mut xof = hasher.finalize_xof();
            let mut xof_bytes = vec![0u8; 3 * 256 * 2]; // enough for rejection sampling
            xof.read(&mut xof_bytes);

            a_hat[i][j] = match sample_ntt_from_bytes(&xof_bytes) {
                Ok(poly) => poly,
                Err(_) => {
                    // Extremely unlikely — try with more bytes.
                    let mut more_bytes = vec![0u8; 3 * 256 * 4];
                    let mut hasher2 = Shake128::default();
                    hasher2.update(&seed);
                    let mut xof2 = hasher2.finalize_xof();
                    xof2.read(&mut more_bytes);
                    sample_ntt_from_bytes(&more_bytes).expect("SampleNTT failed with extended bytes")
                }
            };
        }
    }
    a_hat
}

/// PRF_eta(s, b) = SHAKE256(s || b, 8 * 64 * eta) per FIPS 203 Eq. 4.3.
fn prf(eta: usize, s: &[u8], b: u8) -> Vec<u8> {
    let output_len = 64 * eta;
    let mut input = Vec::with_capacity(33);
    input.extend_from_slice(s);
    input.push(b);
    shake256(&input, output_len)
}

fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, data);
    hasher.finalize().into()
}

fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, data);
    hasher.finalize().into()
}

fn shake256(data: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut xof = hasher.finalize_xof();
    let mut output = vec![0u8; output_len];
    xof.read(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::ML_KEM_768;

    #[test]
    fn keygen_deterministic() {
        let d = [0u8; 32];
        let z = [1u8; 32];
        let kp1 = ml_kem_keygen_internal(&d, &z, &ML_KEM_768);
        let kp2 = ml_kem_keygen_internal(&d, &z, &ML_KEM_768);
        assert_eq!(kp1.ek, kp2.ek, "keygen must be deterministic");
        assert_eq!(kp1.dk, kp2.dk, "keygen must be deterministic");
    }

    #[test]
    fn encaps_deterministic() {
        let d = [0u8; 32];
        let z = [1u8; 32];
        let kp = ml_kem_keygen_internal(&d, &z, &ML_KEM_768);
        let m = [2u8; 32];
        let (ct1, ss1) = ml_kem_encaps_internal(&kp.ek, &m, &ML_KEM_768);
        let (ct2, ss2) = ml_kem_encaps_internal(&kp.ek, &m, &ML_KEM_768);
        assert_eq!(ct1, ct2, "encaps must be deterministic");
        assert_eq!(ss1, ss2, "encaps must be deterministic");
    }

    #[test]
    fn keygen_key_sizes() {
        let d = [0u8; 32];
        let z = [0u8; 32];
        for params in crate::params::ALL_PARAMS {
            let kp = ml_kem_keygen_internal(&d, &z, params);
            let expected_ek_len = 384 * params.k + 32;
            let expected_dk_len = 384 * params.k + expected_ek_len + 32 + 32;
            assert_eq!(
                kp.ek.len(),
                expected_ek_len,
                "{}: ek length mismatch",
                params.name
            );
            assert_eq!(
                kp.dk.len(),
                expected_dk_len,
                "{}: dk length mismatch",
                params.name
            );
        }
    }
}
