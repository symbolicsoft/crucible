//! Pseudorandom sampling per FIPS 204 §7.3.
//! SampleInBall, RejNTTPoly, RejBoundedPoly, ExpandA, ExpandS, ExpandMask.

use crate::params::{MlDsaParams, N, Q};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

/// SampleInBall(ρ): sample challenge polynomial c ∈ B_τ. (Algorithm 29)
/// c has exactly τ nonzero coefficients, all ±1.
pub fn sample_in_ball(rho: &[u8], tau: usize) -> [i32; N] {
    let mut c = [0i32; N];

    let mut hasher = Shake256::default();
    hasher.update(rho);
    let mut xof = hasher.finalize_xof();

    // Read first 8 bytes for sign bits.
    let mut sign_bytes = [0u8; 8];
    xof.read(&mut sign_bytes);
    let signs = u64::from_le_bytes(sign_bytes);

    // Fisher-Yates shuffle.
    for i in (N - tau)..N {
        // Rejection sample j in [0, i].
        let j = loop {
            let mut buf = [0u8; 1];
            xof.read(&mut buf);
            let j = buf[0] as usize;
            if j <= i {
                break j;
            }
        };

        c[i] = c[j];
        let sign_bit = (signs >> (i + tau - N)) & 1;
        c[j] = if sign_bit == 0 { 1 } else { -1 };
    }

    c
}

/// RejNTTPoly(ρ): rejection-sample an element of T_q. (Algorithm 30)
/// Uses SHAKE128 (G) for XOF.
pub fn rej_ntt_poly(rho: &[u8]) -> [i32; N] {
    let mut a_hat = [0i32; N];
    let mut j = 0usize;

    let mut hasher = Shake128::default();
    hasher.update(rho);
    let mut xof = hasher.finalize_xof();

    while j < N {
        let mut buf = [0u8; 3];
        xof.read(&mut buf);
        let val = coeff_from_three_bytes(buf[0], buf[1], buf[2]);
        if let Some(v) = val {
            a_hat[j] = v;
            j += 1;
        }
    }

    a_hat
}

/// CoeffFromThreeBytes (Algorithm 14): generate element of [0, q-1] or reject.
fn coeff_from_three_bytes(b0: u8, b1: u8, b2: u8) -> Option<i32> {
    let mut b2_prime = b2;
    if b2_prime > 127 {
        b2_prime -= 128;
    }
    let z = (b2_prime as u32) * 65536 + (b1 as u32) * 256 + b0 as u32;
    if z < Q {
        Some(z as i32)
    } else {
        None
    }
}

/// RejBoundedPoly(ρ): sample polynomial with coefficients in [-η, η]. (Algorithm 31)
/// Uses SHAKE256 (H) for XOF.
pub fn rej_bounded_poly(rho: &[u8], eta: u32) -> [i32; N] {
    let mut a = [0i32; N];
    let mut j = 0usize;

    let mut hasher = Shake256::default();
    hasher.update(rho);
    let mut xof = hasher.finalize_xof();

    while j < N {
        let mut buf = [0u8; 1];
        xof.read(&mut buf);
        let z0 = coeff_from_half_byte(buf[0] & 0x0F, eta);
        let z1 = coeff_from_half_byte(buf[0] >> 4, eta);

        if let Some(v) = z0 {
            a[j] = v;
            j += 1;
        }
        if j < N {
            if let Some(v) = z1 {
                a[j] = v;
                j += 1;
            }
        }
    }

    a
}

/// CoeffFromHalfByte (Algorithm 15).
fn coeff_from_half_byte(b: u8, eta: u32) -> Option<i32> {
    match eta {
        2 => {
            if b < 15 {
                Some(2 - (b as i32 % 5))
            } else {
                None
            }
        }
        4 => {
            if b < 9 {
                Some(4 - b as i32)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// ExpandA(ρ): generate matrix Â ∈ T_q^{k×ℓ}. (Algorithm 32)
pub fn expand_a(rho: &[u8; 32], params: &MlDsaParams) -> Vec<Vec<[i32; N]>> {
    let mut a_hat = vec![vec![[0i32; N]; params.l]; params.k];
    for r in 0..params.k {
        for s in 0..params.l {
            let mut seed = Vec::with_capacity(34);
            seed.extend_from_slice(rho);
            seed.push(s as u8);
            seed.push(r as u8);
            a_hat[r][s] = rej_ntt_poly(&seed);
        }
    }
    a_hat
}

/// ExpandS(ρ'): generate secret vectors s₁ ∈ R^ℓ, s₂ ∈ R^k. (Algorithm 33)
pub fn expand_s(rho_prime: &[u8; 64], params: &MlDsaParams) -> (Vec<[i32; N]>, Vec<[i32; N]>) {
    let mut s1 = Vec::with_capacity(params.l);
    for r in 0..params.l {
        let mut seed = Vec::with_capacity(66);
        seed.extend_from_slice(rho_prime);
        seed.extend_from_slice(&(r as u16).to_le_bytes());
        s1.push(rej_bounded_poly(&seed, params.eta));
    }

    let mut s2 = Vec::with_capacity(params.k);
    for r in 0..params.k {
        let mut seed = Vec::with_capacity(66);
        seed.extend_from_slice(rho_prime);
        seed.extend_from_slice(&((r + params.l) as u16).to_le_bytes());
        s2.push(rej_bounded_poly(&seed, params.eta));
    }

    (s1, s2)
}

/// ExpandMask(ρ", κ): generate masking vector y ∈ R^ℓ. (Algorithm 34)
pub fn expand_mask(rho_pp: &[u8; 64], kappa: usize, params: &MlDsaParams) -> Vec<[i32; N]> {
    let gamma1 = params.gamma1;
    let c = 1 + bit_length(gamma1 - 1);
    let mut y = Vec::with_capacity(params.l);

    for r in 0..params.l {
        let mut seed = Vec::with_capacity(66);
        seed.extend_from_slice(rho_pp);
        seed.extend_from_slice(&((kappa + r) as u16).to_le_bytes());

        let v = shake256_bytes(&seed, 32 * c);
        y.push(bit_unpack(&v, gamma1 as i32 - 1, gamma1 as i32));
    }

    y
}

/// BitUnpack: unpack bytes into polynomial with coefficients in [-a, b].
fn bit_unpack(v: &[u8], a: i32, b: i32) -> [i32; N] {
    let c = bit_length((a + b) as u32);
    let bits = bytes_to_bits(v);
    let mut w = [0i32; N];
    for i in 0..N {
        let mut val = 0u32;
        for j in (0..c).rev() {
            if i * c + j < bits.len() {
                val = 2 * val + bits[i * c + j] as u32;
            }
        }
        w[i] = b - val as i32;
    }
    w
}

fn bit_length(a: u32) -> usize {
    if a == 0 { return 1; }
    32 - a.leading_zeros() as usize
}

fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = vec![0u8; bytes.len() * 8];
    for i in 0..bytes.len() {
        for j in 0..8 {
            bits[8 * i + j] = (bytes[i] >> j) & 1;
        }
    }
    bits
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
    use crate::params::ML_DSA_44;

    #[test]
    fn sample_in_ball_properties() {
        let rho = [0x42u8; 32];
        let c = sample_in_ball(&rho, ML_DSA_44.tau);

        // Exactly τ nonzero coefficients.
        let nonzero = c.iter().filter(|&&x| x != 0).count();
        assert_eq!(nonzero, ML_DSA_44.tau);

        // All nonzero are ±1.
        for &coeff in &c {
            assert!(coeff == 0 || coeff == 1 || coeff == -1);
        }
    }

    #[test]
    fn rej_bounded_poly_range() {
        let rho = [0u8; 66];
        for &eta in &[2, 4] {
            let a = rej_bounded_poly(&rho, eta);
            for &coeff in &a {
                assert!(
                    coeff >= -(eta as i32) && coeff <= eta as i32,
                    "coeff {coeff} outside [-{eta}, {eta}]"
                );
            }
        }
    }

    #[test]
    fn rej_ntt_poly_range() {
        let rho = [0x37u8; 34];
        let a = rej_ntt_poly(&rho);
        for &coeff in &a {
            assert!(coeff >= 0 && coeff < Q as i32);
        }
    }
}
