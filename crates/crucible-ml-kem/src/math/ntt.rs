use crate::params::{N, Q, ZETA};

/// Precomputed zeta powers: ζ^{BitRev7(i)} for i = 0..127.
/// Per FIPS 203 §4.3 and Appendix A.
fn zeta_powers() -> [u32; 128] {
    let mut zetas = [0u32; 128];
    for i in 0..128u32 {
        let br = bit_rev7(i);
        zetas[i as usize] = power_mod(ZETA, br, Q);
    }
    zetas
}

/// BitRev7: reverse the 7 least significant bits of an integer.
fn bit_rev7(r: u32) -> u32 {
    let mut result = 0u32;
    let mut val = r;
    for _ in 0..7 {
        result = (result << 1) | (val & 1);
        val >>= 1;
    }
    result
}

/// Modular exponentiation: base^exp mod modulus.
fn power_mod(base: u32, exp: u32, modulus: u32) -> u32 {
    let mut result = 1u64;
    let mut base = base as u64 % modulus as u64;
    let mut exp = exp;
    let m = modulus as u64;

    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % m;
        }
        exp >>= 1;
        base = base * base % m;
    }
    result as u32
}

/// Forward NTT: R_q → T_q.
/// Per FIPS 203 Algorithm 9.
///
/// The algorithm iterates with len = 128, 64, 32, ..., 2 and uses
/// zetas[1], zetas[2], ..., zetas[127] in order.
///
/// Input: array f ∈ ℤ_q^256 (coefficients of a polynomial in R_q).
/// Output: array f_hat ∈ ℤ_q^256 (NTT representation in T_q).
pub fn ntt(f: &[u32; N]) -> [u32; N] {
    let zetas = zeta_powers();
    let mut f_hat = *f;
    let q = Q as u64;

    let mut i = 1usize; // zeta index, per Algorithm 9
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < 256 {
            let zeta = zetas[i] as u64;
            i += 1;
            for j in start..(start + len) {
                let t = (zeta * f_hat[j + len] as u64) % q;
                f_hat[j + len] = ((f_hat[j] as u64 + q - t) % q) as u32;
                f_hat[j] = ((f_hat[j] as u64 + t) % q) as u32;
            }
            start += 2 * len;
        }
        len /= 2;
    }

    f_hat
}

/// Inverse NTT: T_q → R_q.
/// Per FIPS 203 Algorithm 10.
///
/// The algorithm iterates with len = 2, 4, 8, ..., 128 and uses
/// zetas[127], zetas[126], ..., zetas[1] in reverse order.
/// Final multiply by 3303 = 128^{-1} mod q.
///
/// Input: array f_hat ∈ ℤ_q^256 (NTT representation).
/// Output: array f ∈ ℤ_q^256 (polynomial coefficients).
pub fn inv_ntt(f_hat: &[u32; N]) -> [u32; N] {
    let zetas = zeta_powers();
    let mut f = *f_hat;
    let q = Q as u64;

    let mut i = 127usize; // zeta index, counting down, per Algorithm 10
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < 256 {
            let zeta = zetas[i] as u64;
            i -= 1;
            for j in start..(start + len) {
                let t = f[j] as u64;
                f[j] = ((t + f[j + len] as u64) % q) as u32;
                f[j + len] = ((zeta * (f[j + len] as u64 + q - t)) % q) as u32;
            }
            start += 2 * len;
        }
        len *= 2;
    }

    // Algorithm 10 multiplies by f^{-1} = 3303 = 128^{-1} mod q.
    // Note: the FIPS 203 NTT uses 128 butterflies, not 256, so the
    // normalization factor is 128^{-1}, not 256^{-1}.
    let f_inv = mod_inverse(128, Q);
    for coeff in &mut f {
        *coeff = ((*coeff as u64 * f_inv as u64) % q) as u32;
    }

    f
}

/// MultiplyNTTs: pointwise multiplication in T_q.
/// Per FIPS 203 Algorithm 11.
///
/// Multiplies two NTT representations by applying BaseCaseMultiply
/// to each of the 128 pairs of degree-1 polynomials.
/// The i-th pair uses gamma = ζ^{2·BitRev7(i)+1}.
pub fn multiply_ntts(f_hat: &[u32; N], g_hat: &[u32; N]) -> [u32; N] {
    let mut h_hat = [0u32; N];

    for i in 0..64u32 {
        // Per Algorithm 11: two BaseCaseMultiply calls per iteration.
        // γ for slots (4i, 4i+1) = ζ^{2·BitRev7(2i)+1}
        // γ for slots (4i+2, 4i+3) = ζ^{2·BitRev7(2i+1)+1} = -γ (since ζ^128 = -1)
        let gamma = power_mod(ZETA, 2 * bit_rev7(2 * i) + 1, Q);

        let (c0, c1) = base_case_multiply(
            f_hat[4 * i as usize],
            f_hat[4 * i as usize + 1],
            g_hat[4 * i as usize],
            g_hat[4 * i as usize + 1],
            gamma,
        );
        h_hat[4 * i as usize] = c0;
        h_hat[4 * i as usize + 1] = c1;

        // Second pair uses -γ.
        let (c0, c1) = base_case_multiply(
            f_hat[4 * i as usize + 2],
            f_hat[4 * i as usize + 3],
            g_hat[4 * i as usize + 2],
            g_hat[4 * i as usize + 3],
            Q - gamma,
        );
        h_hat[4 * i as usize + 2] = c0;
        h_hat[4 * i as usize + 3] = c1;
    }

    h_hat
}

/// BaseCaseMultiply: multiply two degree-1 polynomials mod (X² - γ).
/// Per FIPS 203 Algorithm 12.
///
/// (a0 + a1·X) · (b0 + b1·X) mod (X² - γ)
/// = (a0·b0 + a1·b1·γ) + (a0·b1 + a1·b0)·X
pub fn base_case_multiply(a0: u32, a1: u32, b0: u32, b1: u32, gamma: u32) -> (u32, u32) {
    let q = Q as u64;
    let a1b1 = (a1 as u64 * b1 as u64) % q;
    let c0 = ((a0 as u64 * b0 as u64 + a1b1 * gamma as u64) % q) as u32;
    let c1 = ((a0 as u64 * b1 as u64 + a1 as u64 * b0 as u64) % q) as u32;
    (c0, c1)
}

/// Compute modular inverse using extended Euclidean algorithm.
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

/// Get the precomputed zeta table (for tests to verify against implementations).
pub fn get_zeta_table() -> [u32; 128] {
    zeta_powers()
}

/// Schoolbook polynomial multiplication in R_q = ℤ_q[X]/(X^256 + 1).
/// Used as a reference to verify NTT-based multiplication.
pub fn schoolbook_multiply(a: &[u32; N], b: &[u32; N]) -> [u32; N] {
    let q = Q as u64;
    let mut c = [0u64; 2 * N];

    for i in 0..N {
        for j in 0..N {
            c[i + j] += a[i] as u64 * b[j] as u64;
        }
    }

    // Reduce mod X^256 + 1: coefficient of X^(256+k) wraps to -1 * coefficient of X^k.
    let mut result = [0u32; N];
    for i in 0..N {
        let pos = c[i] % q;
        let neg = c[i + N] % q;
        result[i] = ((pos + q - neg) % q) as u32;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntt_inv_ntt_round_trip() {
        // Zero polynomial.
        let f = [0u32; N];
        assert_eq!(inv_ntt(&ntt(&f)), f);

        // Constant polynomial = 1.
        let mut f1 = [0u32; N];
        f1[0] = 1;
        assert_eq!(inv_ntt(&ntt(&f1)), f1);

        // X (monomial).
        let mut fx = [0u32; N];
        fx[1] = 1;
        assert_eq!(inv_ntt(&ntt(&fx)), fx);

        // All coefficients = 1.
        let f_ones = [1u32; N];
        assert_eq!(inv_ntt(&ntt(&f_ones)), f_ones);

        // Max coefficients.
        let f_max = [Q - 1; N];
        assert_eq!(inv_ntt(&ntt(&f_max)), f_max);
    }

    #[test]
    fn ntt_multiply_matches_schoolbook() {
        // f = 1 + X, g = 1 + X
        let mut f = [0u32; N];
        f[0] = 1;
        f[1] = 1;
        let mut g = [0u32; N];
        g[0] = 1;
        g[1] = 1;

        let expected = schoolbook_multiply(&f, &g);
        let ntt_result = inv_ntt(&multiply_ntts(&ntt(&f), &ntt(&g)));

        assert_eq!(ntt_result, expected);
    }

    #[test]
    fn ntt_multiply_random_matches_schoolbook() {
        // Use a deterministic "random" polynomial.
        let mut f = [0u32; N];
        let mut g = [0u32; N];
        let mut seed = 42u64;
        for i in 0..N {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            f[i] = (seed >> 33) as u32 % Q;
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            g[i] = (seed >> 33) as u32 % Q;
        }

        let expected = schoolbook_multiply(&f, &g);
        let ntt_result = inv_ntt(&multiply_ntts(&ntt(&f), &ntt(&g)));

        assert_eq!(ntt_result, expected);
    }

    #[test]
    fn bit_rev7_correct() {
        assert_eq!(bit_rev7(0), 0);
        assert_eq!(bit_rev7(1), 64);
        assert_eq!(bit_rev7(64), 1);
        assert_eq!(bit_rev7(127), 127);
    }

    #[test]
    fn mod_inverse_correct() {
        let inv = mod_inverse(256, Q);
        assert_eq!((256u64 * inv as u64) % Q as u64, 1);
    }

    #[test]
    fn zeta_is_primitive_256th_root() {
        // ζ^128 ≡ -1 (mod q), i.e., ζ^128 + 1 ≡ 0.
        let z128 = power_mod(ZETA, 128, Q);
        assert_eq!(z128, Q - 1, "ζ^128 should be -1 mod q");

        // ζ^256 ≡ 1 (mod q).
        let z256 = power_mod(ZETA, 256, Q);
        assert_eq!(z256, 1, "ζ^256 should be 1 mod q");

        // ζ^128 ≢ 1 (mod q) — it's a primitive root, not just any root.
        assert_ne!(z128, 1, "ζ^128 should not be 1 mod q");
    }
}
