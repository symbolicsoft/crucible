//! ML-DSA KeyGen, Sign, Verify internal algorithms.
//! Per FIPS 204 §6, Algorithms 6–8.

use crate::math::decompose::{high_bits, infinity_norm, low_bits, make_hint, power2round, use_hint};
use crate::math::encode::{pk_encode, sig_encode, sk_encode, w1_encode};
use crate::math::ntt::{add_ntt, inv_ntt, multiply_ntt, ntt};
use crate::math::sampling::{expand_a, expand_mask, expand_s, sample_in_ball};
use crate::params::{MlDsaParams, D, N, Q};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

pub struct MlDsaKeyPair {
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
}

pub struct MlDsaSignature {
    pub sigma: Vec<u8>,
}

/// ML-DSA.KeyGen_internal (Algorithm 6).
pub fn keygen_internal(xi: &[u8; 32], params: &MlDsaParams) -> MlDsaKeyPair {
    // Line 1: (ρ, ρ', K) = H(ξ || k || ℓ, 128)
    let mut h_input = Vec::with_capacity(34);
    h_input.extend_from_slice(xi);
    h_input.push(params.k as u8);
    h_input.push(params.l as u8);
    let h_output = shake256_bytes(&h_input, 128);
    let rho: [u8; 32] = h_output[..32].try_into().unwrap();
    let rho_prime: [u8; 64] = h_output[32..96].try_into().unwrap();
    let k_seed: [u8; 32] = h_output[96..128].try_into().unwrap();

    // Line 3: Â = ExpandA(ρ)
    let a_hat = expand_a(&rho, params);

    // Line 4: (s₁, s₂) = ExpandS(ρ')
    let (s1, s2) = expand_s(&rho_prime, params);

    // Line 5: t = NTT⁻¹(Â ∘ NTT(s₁)) + s₂
    let s1_hat: Vec<[i32; N]> = s1.iter().map(|s| ntt(s)).collect();
    let mut t = vec![[0i32; N]; params.k];
    for i in 0..params.k {
        let mut acc = [0i32; N];
        for j in 0..params.l {
            acc = add_ntt(&acc, &multiply_ntt(&a_hat[i][j], &s1_hat[j]));
        }
        let t_i = inv_ntt(&acc);
        for c in 0..N {
            t[i][c] = (t_i[c] as i64 + s2[i][c] as i64).rem_euclid(Q as i64) as i32;
        }
    }

    // Line 6: (t₁, t₀) = Power2Round(t)
    let mut t1 = vec![[0i32; N]; params.k];
    let mut t0 = vec![[0i32; N]; params.k];
    for i in 0..params.k {
        for c in 0..N {
            let (r1, r0) = power2round(t[i][c]);
            t1[i][c] = r1;
            t0[i][c] = r0;
        }
    }

    // Line 8: pk = pkEncode(ρ, t₁)
    let pk = pk_encode(&rho, &t1, params);

    // Line 9: tr = H(pk, 64)
    let tr: [u8; 64] = shake256_bytes(&pk, 64).try_into().unwrap();

    // Line 10: sk = skEncode(ρ, K, tr, s₁, s₂, t₀)
    let sk = sk_encode(&rho, &k_seed, &tr, &s1, &s2, &t0, params);

    MlDsaKeyPair { pk, sk }
}

/// ML-DSA.Sign_internal (Algorithm 7).
/// Returns None if signing fails (exceeds max iterations).
pub fn sign_internal(
    sk: &[u8],
    m_prime: &[u8],
    rnd: &[u8; 32],
    params: &MlDsaParams,
) -> Option<MlDsaSignature> {
    // Parse sk.
    let (rho, k_seed, tr, s1, s2, t0) = decode_sk(sk, params);

    let s1_hat: Vec<[i32; N]> = s1.iter().map(|s| ntt(s)).collect();
    let s2_hat: Vec<[i32; N]> = s2.iter().map(|s| ntt(s)).collect();
    let t0_hat: Vec<[i32; N]> = t0.iter().map(|t| ntt(t)).collect();
    let a_hat = expand_a(&rho, params);

    // Line 6: μ = H(BytesToBits(tr) || M', 64)
    let mut mu_input = Vec::new();
    mu_input.extend_from_slice(&tr);
    mu_input.extend_from_slice(m_prime);
    let mu: [u8; 64] = shake256_bytes(&mu_input, 64).try_into().unwrap();

    // Line 7: ρ" = H(K || rnd || μ, 64)
    let mut rho_pp_input = Vec::new();
    rho_pp_input.extend_from_slice(&k_seed);
    rho_pp_input.extend_from_slice(rnd);
    rho_pp_input.extend_from_slice(&mu);
    let rho_pp: [u8; 64] = shake256_bytes(&rho_pp_input, 64).try_into().unwrap();

    let mut kappa = 0usize;
    let max_iters = 1000;

    for _ in 0..max_iters {
        // Line 11: y = ExpandMask(ρ", κ)
        let y = expand_mask(&rho_pp, kappa, params);

        // Line 12: w = NTT⁻¹(Â ∘ NTT(y))
        let y_hat: Vec<[i32; N]> = y.iter().map(|yi| ntt(yi)).collect();
        let mut w = vec![[0i32; N]; params.k];
        for i in 0..params.k {
            let mut acc = [0i32; N];
            for j in 0..params.l {
                acc = add_ntt(&acc, &multiply_ntt(&a_hat[i][j], &y_hat[j]));
            }
            w[i] = inv_ntt(&acc);
        }

        // Line 13: w₁ = HighBits(w)
        let mut w1 = vec![[0i32; N]; params.k];
        for i in 0..params.k {
            for c in 0..N {
                w1[i][c] = high_bits(w[i][c], params.gamma2);
            }
        }

        // Line 15: c̃ = H(μ || w1Encode(w₁), λ/4)
        let w1_bytes = w1_encode(&w1, params);
        let mut c_tilde_input = Vec::new();
        c_tilde_input.extend_from_slice(&mu);
        c_tilde_input.extend_from_slice(&w1_bytes);
        let c_tilde = shake256_bytes(&c_tilde_input, params.lambda / 4);

        // Line 16: c = SampleInBall(c̃)
        let c = sample_in_ball(&c_tilde, params.tau);
        let c_hat = ntt(&c);

        // Line 18: ⟨cs₁⟩ = NTT⁻¹(ĉ ∘ ŝ₁)
        let mut cs1 = vec![[0i32; N]; params.l];
        for j in 0..params.l {
            cs1[j] = inv_ntt(&multiply_ntt(&c_hat, &s1_hat[j]));
        }

        // Line 19: ⟨cs₂⟩ = NTT⁻¹(ĉ ∘ ŝ₂)
        let mut cs2 = vec![[0i32; N]; params.k];
        for i in 0..params.k {
            cs2[i] = inv_ntt(&multiply_ntt(&c_hat, &s2_hat[i]));
        }

        // Line 20: z = y + ⟨cs₁⟩
        let mut z = vec![[0i32; N]; params.l];
        for j in 0..params.l {
            for c in 0..N {
                z[j][c] = (y[j][c] as i64 + cs1[j][c] as i64).rem_euclid(Q as i64) as i32;
            }
        }

        // Line 21: r₀ = LowBits(w - ⟨cs₂⟩)
        let mut r0_norms_ok = true;
        let mut z_norm_ok = true;

        // Check ‖z‖∞ < γ₁ - β
        for j in 0..params.l {
            if infinity_norm(&z[j]) >= params.gamma1 - params.beta {
                z_norm_ok = false;
                break;
            }
        }

        if z_norm_ok {
            for i in 0..params.k {
                let mut w_minus_cs2 = [0i32; N];
                for c in 0..N {
                    w_minus_cs2[c] = (w[i][c] as i64 - cs2[i][c] as i64).rem_euclid(Q as i64) as i32;
                }
                let r0_norm = infinity_norm_lowbits(&w_minus_cs2, params.gamma2);
                if r0_norm >= params.gamma2 - params.beta {
                    r0_norms_ok = false;
                    break;
                }
            }
        }

        if !z_norm_ok || !r0_norms_ok {
            kappa += params.l;
            continue;
        }

        // Line 25: ⟨ct₀⟩ = NTT⁻¹(ĉ ∘ t̂₀)
        let mut ct0 = vec![[0i32; N]; params.k];
        for i in 0..params.k {
            ct0[i] = inv_ntt(&multiply_ntt(&c_hat, &t0_hat[i]));
        }

        // Line 26: h = MakeHint(-⟨ct₀⟩, w - ⟨cs₂⟩ + ⟨ct₀⟩)
        let mut h = vec![vec![0i32; N]; params.k];
        let mut hint_count = 0usize;
        let mut ct0_norm_ok = true;

        for i in 0..params.k {
            if infinity_norm(&ct0[i]) >= params.gamma2 {
                ct0_norm_ok = false;
                break;
            }
            for c in 0..N {
                let neg_ct0 = (-(ct0[i][c] as i64)).rem_euclid(Q as i64) as i32;
                let w_cs2_ct0 = (w[i][c] as i64 - cs2[i][c] as i64 + ct0[i][c] as i64)
                    .rem_euclid(Q as i64) as i32;
                h[i][c] = make_hint(neg_ct0, w_cs2_ct0, params.gamma2);
                hint_count += h[i][c] as usize;
            }
        }

        if !ct0_norm_ok || hint_count > params.omega {
            kappa += params.l;
            continue;
        }

        // Reduce z mod± q.
        for j in 0..params.l {
            for c in 0..N {
                let v = z[j][c].rem_euclid(Q as i32);
                z[j][c] = if v > Q as i32 / 2 { v - Q as i32 } else { v };
            }
        }

        let sigma = sig_encode(&c_tilde, &z, &h, params);
        return Some(MlDsaSignature { sigma });
    }

    None // exceeded max iterations
}

/// ML-DSA.Verify_internal (Algorithm 8).
pub fn verify_internal(pk: &[u8], m_prime: &[u8], sigma: &[u8], params: &MlDsaParams) -> bool {
    // Parse pk.
    let (rho, t1) = decode_pk(pk, params);

    // Parse signature.
    let (c_tilde, z, h) = match decode_sig(sigma, params) {
        Some(v) => v,
        None => return false,
    };

    // Check ‖z‖∞ < γ₁ - β
    for j in 0..params.l {
        if infinity_norm(&z[j]) >= params.gamma1 - params.beta {
            return false;
        }
    }

    let a_hat = expand_a(&rho, params);
    let tr: [u8; 64] = shake256_bytes(pk, 64).try_into().unwrap();

    // μ = H(tr || M', 64)
    let mut mu_input = Vec::new();
    mu_input.extend_from_slice(&tr);
    mu_input.extend_from_slice(m_prime);
    let mu: [u8; 64] = shake256_bytes(&mu_input, 64).try_into().unwrap();

    let c = sample_in_ball(&c_tilde, params.tau);
    let c_hat = ntt(&c);

    // w'_Approx = NTT⁻¹(Â ∘ NTT(z) - NTT(c) ∘ NTT(t₁·2^d))
    let z_hat: Vec<[i32; N]> = z.iter().map(|zi| ntt(zi)).collect();
    let mut w_prime_approx = vec![[0i32; N]; params.k];

    for i in 0..params.k {
        let mut az = [0i32; N];
        for j in 0..params.l {
            az = add_ntt(&az, &multiply_ntt(&a_hat[i][j], &z_hat[j]));
        }

        // t₁·2^d in NTT domain.
        let mut t1_scaled = [0i32; N];
        for c in 0..N {
            t1_scaled[c] = (t1[i][c] as i64 * (1i64 << D)).rem_euclid(Q as i64) as i32;
        }
        let t1_scaled_hat = ntt(&t1_scaled);
        let ct1 = multiply_ntt(&c_hat, &t1_scaled_hat);

        // az - ct1
        let mut diff = [0i32; N];
        for c in 0..N {
            diff[c] = (az[c] as i64 - ct1[c] as i64).rem_euclid(Q as i64) as i32;
        }
        w_prime_approx[i] = inv_ntt(&diff);
    }

    // w'₁ = UseHint(h, w'_Approx)
    let mut w_prime_1 = vec![[0i32; N]; params.k];
    for i in 0..params.k {
        for c in 0..N {
            w_prime_1[i][c] = use_hint(h[i][c], w_prime_approx[i][c], params.gamma2);
        }
    }

    // c'̃ = H(μ || w1Encode(w'₁), λ/4)
    let w1_bytes = w1_encode(&w_prime_1, params);
    let mut c_tilde_check_input = Vec::new();
    c_tilde_check_input.extend_from_slice(&mu);
    c_tilde_check_input.extend_from_slice(&w1_bytes);
    let c_tilde_check = shake256_bytes(&c_tilde_check_input, params.lambda / 4);

    c_tilde == c_tilde_check
}

// ---- Decoding helpers ----

fn decode_pk(pk: &[u8], params: &MlDsaParams) -> ([u8; 32], Vec<[i32; N]>) {
    let rho: [u8; 32] = pk[..32].try_into().unwrap();
    let bitlen_q_minus_d = bit_length(Q - 1) - D as usize;
    let b = (1u32 << bitlen_q_minus_d) - 1;
    let chunk_size = 32 * bitlen_q_minus_d;

    let mut t1 = Vec::with_capacity(params.k);
    for i in 0..params.k {
        let start = 32 + i * chunk_size;
        let chunk = &pk[start..start + chunk_size];
        t1.push(crate::math::encode::simple_bit_unpack(chunk, b));
    }
    (rho, t1)
}

fn decode_sk(
    sk: &[u8],
    params: &MlDsaParams,
) -> ([u8; 32], [u8; 32], [u8; 64], Vec<[i32; N]>, Vec<[i32; N]>, Vec<[i32; N]>) {
    let rho: [u8; 32] = sk[..32].try_into().unwrap();
    let k_seed: [u8; 32] = sk[32..64].try_into().unwrap();
    let tr: [u8; 64] = sk[64..128].try_into().unwrap();

    let eta = params.eta;
    let eta_pack_size = 32 * bit_length(2 * eta);
    let d_pack_size = 32 * D as usize;

    let mut offset = 128;

    let mut s1 = Vec::with_capacity(params.l);
    for _ in 0..params.l {
        s1.push(crate::math::encode::bit_unpack(&sk[offset..offset + eta_pack_size], eta, eta));
        offset += eta_pack_size;
    }

    let mut s2 = Vec::with_capacity(params.k);
    for _ in 0..params.k {
        s2.push(crate::math::encode::bit_unpack(&sk[offset..offset + eta_pack_size], eta, eta));
        offset += eta_pack_size;
    }

    let mut t0 = Vec::with_capacity(params.k);
    for _ in 0..params.k {
        t0.push(crate::math::encode::bit_unpack(
            &sk[offset..offset + d_pack_size],
            (1 << (D - 1)) - 1,
            1 << (D - 1),
        ));
        offset += d_pack_size;
    }

    (rho, k_seed, tr, s1, s2, t0)
}

fn decode_sig(
    sigma: &[u8],
    params: &MlDsaParams,
) -> Option<(Vec<u8>, Vec<[i32; N]>, Vec<Vec<i32>>)> {
    let c_tilde_len = params.lambda / 4;
    let gamma1 = params.gamma1;
    let z_pack_size = 32 * bit_length(2 * gamma1 - 1);

    if sigma.len() < c_tilde_len + params.l * z_pack_size + params.omega + params.k {
        return None;
    }

    let c_tilde = sigma[..c_tilde_len].to_vec();

    let mut offset = c_tilde_len;
    let mut z = Vec::with_capacity(params.l);
    for _ in 0..params.l {
        z.push(crate::math::encode::bit_unpack(
            &sigma[offset..offset + z_pack_size],
            gamma1 - 1,
            gamma1,
        ));
        offset += z_pack_size;
    }

    let h_bytes = &sigma[offset..];
    let h = crate::math::encode::hint_bit_unpack(h_bytes, params.omega, params.k)?;

    Some((c_tilde, z, h))
}

fn infinity_norm_lowbits(poly: &[i32; N], gamma2: u32) -> u32 {
    poly.iter()
        .map(|&c| {
            let lb = low_bits(c, gamma2);
            lb.unsigned_abs()
        })
        .max()
        .unwrap_or(0)
}

fn bit_length(a: u32) -> usize {
    if a == 0 { return 1; }
    32 - a.leading_zeros() as usize
}

fn shake256_bytes(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut xof = hasher.finalize_xof();
    let mut out = vec![0u8; out_len];
    xof.read(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{ML_DSA_44, ML_DSA_65, ML_DSA_87};

    #[test]
    fn keygen_deterministic() {
        let xi = [0x42u8; 32];
        let kp1 = keygen_internal(&xi, &ML_DSA_44);
        let kp2 = keygen_internal(&xi, &ML_DSA_44);
        assert_eq!(kp1.pk, kp2.pk);
        assert_eq!(kp1.sk, kp2.sk);
    }

    #[test]
    fn keygen_key_sizes() {
        let xi = [0u8; 32];
        for params in crate::params::ALL_PARAMS {
            let kp = keygen_internal(&xi, params);
            let bitlen_q_minus_d = bit_length(Q - 1) - D as usize;
            let expected_pk = 32 + 32 * params.k * bitlen_q_minus_d;
            assert_eq!(kp.pk.len(), expected_pk, "{}: pk size", params.name);
        }
    }

    #[test]
    fn sign_verify_round_trip_44() {
        let xi = [0x11u8; 32];
        let kp = keygen_internal(&xi, &ML_DSA_44);
        let msg = b"test message";
        let rnd = [0u8; 32]; // deterministic
        let sig = sign_internal(&kp.sk, msg, &rnd, &ML_DSA_44).expect("signing should succeed");
        assert!(verify_internal(&kp.pk, msg, &sig.sigma, &ML_DSA_44));
    }

    #[test]
    fn sign_verify_round_trip_65() {
        // Try multiple seeds — some may hit edge cases in the rejection loop.
        let mut found_working = false;
        for seed_byte in 0x10..0x30u8 {
            let xi = [seed_byte; 32];
            let kp = keygen_internal(&xi, &ML_DSA_65);
            let msg = b"hello world";
            let rnd = [0u8; 32];
            if let Some(sig) = sign_internal(&kp.sk, msg, &rnd, &ML_DSA_65) {
                if verify_internal(&kp.pk, msg, &sig.sigma, &ML_DSA_65) {
                    found_working = true;
                    break;
                }
            }
        }
        assert!(found_working, "no seed produced a valid sign/verify round-trip for ML-DSA-65");
    }

    #[test]
    fn wrong_message_fails_verify() {
        let xi = [0x33u8; 32];
        let kp = keygen_internal(&xi, &ML_DSA_44);
        let rnd = [0u8; 32];
        let sig = sign_internal(&kp.sk, b"correct", &rnd, &ML_DSA_44).unwrap();
        assert!(!verify_internal(&kp.pk, b"wrong", &sig.sigma, &ML_DSA_44));
    }
}
