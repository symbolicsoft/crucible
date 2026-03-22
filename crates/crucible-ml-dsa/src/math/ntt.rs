use crate::params::{N, Q, ZETA};

/// BitRev8: reverse the 8 least significant bits.
pub fn bit_rev8(r: u32) -> u32 {
    let mut result = 0u32;
    let mut val = r;
    for _ in 0..8 {
        result = (result << 1) | (val & 1);
        val >>= 1;
    }
    result
}

/// Modular exponentiation: base^exp mod modulus.
pub fn power_mod(base: u32, exp: u32, modulus: u32) -> u32 {
    let mut result = 1u64;
    let mut b = base as u64 % modulus as u64;
    let mut e = exp;
    let m = modulus as u64;
    while e > 0 {
        if e & 1 == 1 {
            result = result * b % m;
        }
        e >>= 1;
        b = b * b % m;
    }
    result as u32
}

/// Precomputed zetas: ζ^{BitRev8(i)} for i = 0..255.
/// Per FIPS 204 Appendix B.
pub fn zeta_powers() -> [u32; 256] {
    let mut zetas = [0u32; 256];
    for i in 0..256u32 {
        zetas[i as usize] = power_mod(ZETA, bit_rev8(i), Q);
    }
    zetas
}

/// Forward NTT for ML-DSA. Per FIPS 204 Algorithm 41.
/// ζ = 1753 (512th root of unity mod q = 8380417).
/// Uses BitRev8 for zeta indexing.
/// T_q = ∏_{i=0}^{255} ℤ_q (pointwise, not degree-1 pairs like ML-KEM).
pub fn ntt(w: &[i32; N]) -> [i32; N] {
    let zetas = zeta_powers();
    let mut w_hat = *w;
    let q = Q as i64;

    let mut m = 1usize;
    let mut len = 128;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            let z = zetas[m] as i64;
            m += 1;
            for j in start..(start + len) {
                let t = (z * w_hat[j + len] as i64).rem_euclid(q) as i32;
                w_hat[j + len] = (w_hat[j] as i64 - t as i64).rem_euclid(q) as i32;
                w_hat[j] = (w_hat[j] as i64 + t as i64).rem_euclid(q) as i32;
            }
            start += 2 * len;
        }
        len /= 2;
    }

    w_hat
}

/// Inverse NTT for ML-DSA. Per FIPS 204 Algorithm 42.
pub fn inv_ntt(w_hat: &[i32; N]) -> [i32; N] {
    let zetas = zeta_powers();
    let mut w = *w_hat;
    let q = Q as i64;

    let mut m = 255usize;
    let mut len = 1;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let z = zetas[m] as i64;
            m -= 1;
            for j in start..(start + len) {
                let t = w[j] as i64;
                w[j] = (t + w[j + len] as i64).rem_euclid(q) as i32;
                w[j + len] = ((w[j + len] as i64 - t) * z).rem_euclid(q) as i32;
            }
            start += 2 * len;
        }
        len *= 2;
    }

    // Multiply by n^{-1} mod q. n = 256, n^{-1} mod q = ?
    let n_inv = mod_inverse(N as u32, Q) as i64;
    for coeff in &mut w {
        *coeff = (*coeff as i64 * n_inv).rem_euclid(q) as i32;
    }

    w
}

/// Pointwise multiplication in T_q (element-wise for ML-DSA).
/// Per FIPS 204 Algorithm 45.
pub fn multiply_ntt(a_hat: &[i32; N], b_hat: &[i32; N]) -> [i32; N] {
    let q = Q as i64;
    let mut c_hat = [0i32; N];
    for i in 0..N {
        c_hat[i] = (a_hat[i] as i64 * b_hat[i] as i64).rem_euclid(q) as i32;
    }
    c_hat
}

/// Pointwise addition.
pub fn add_ntt(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let q = Q as i64;
    let mut c = [0i32; N];
    for i in 0..N {
        c[i] = (a[i] as i64 + b[i] as i64).rem_euclid(q) as i32;
    }
    c
}

fn mod_inverse(a: u32, m: u32) -> u32 {
    let (mut old_r, mut r) = (a as i64, m as i64);
    let (mut old_s, mut s) = (1i64, 0i64);
    while r != 0 {
        let quotient = old_r / r;
        let tmp = r;
        r = old_r - quotient * r;
        old_r = tmp;
        let tmp = s;
        s = old_s - quotient * s;
        old_s = tmp;
    }
    ((old_s % m as i64 + m as i64) % m as i64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntt_round_trip() {
        let mut w = [0i32; N];
        w[0] = 1;
        assert_eq!(inv_ntt(&ntt(&w)), w);

        let w_ones = [1i32; N];
        assert_eq!(inv_ntt(&ntt(&w_ones)), w_ones);

        let mut w_x = [0i32; N];
        w_x[1] = 1;
        assert_eq!(inv_ntt(&ntt(&w_x)), w_x);
    }

    #[test]
    fn zeta_is_512th_root() {
        // ζ^256 mod q should give us -1 (i.e., q-1) since ζ is a 512th root.
        let z256 = power_mod(ZETA, 256, Q);
        assert_eq!(z256, Q - 1, "ζ^256 should be -1 mod q");

        let z512 = power_mod(ZETA, 512, Q);
        assert_eq!(z512, 1, "ζ^512 should be 1 mod q");
    }
}
