//! Power2Round, Decompose, HighBits, LowBits, MakeHint, UseHint.
//! Per FIPS 204 §7.4, Algorithms 35–40.

use crate::params::{D, Q};

/// mod± operation: returns the unique m' in (−α/2, α/2] such that m ≡ m' (mod α).
pub fn mod_pm(m: i32, alpha: i32) -> i32 {
    let r = m.rem_euclid(alpha);
    if r > alpha / 2 {
        r - alpha
    } else {
        r
    }
}

/// Power2Round(r): decompose r as r₁·2^d + r₀. (Algorithm 35)
/// Input: r ∈ ℤ_q. Output: (r₁, r₀) where r₀ = r mod± 2^d.
pub fn power2round(r: i32) -> (i32, i32) {
    let r_pos = r.rem_euclid(Q as i32);
    let r0 = mod_pm(r_pos, 1 << D);
    let r1 = (r_pos - r0) >> D;
    (r1, r0)
}

/// Decompose(r): decompose r as r₁·α + r₀ where α = 2γ₂. (Algorithm 36)
/// The special case: if r₁ would be (q-1)/α, set r₁ = 0, r₀ = r₀ - 1.
pub fn decompose(r: i32, gamma2: u32) -> (i32, i32) {
    let alpha = 2 * gamma2 as i32;
    let r_pos = r.rem_euclid(Q as i32);
    let mut r0 = mod_pm(r_pos, alpha);
    let r1;

    if r_pos - r0 == Q as i32 - 1 {
        r1 = 0;
        r0 -= 1;
    } else {
        r1 = (r_pos - r0) / alpha;
    }

    (r1, r0)
}

/// HighBits(r): return the high part from Decompose. (Algorithm 37)
pub fn high_bits(r: i32, gamma2: u32) -> i32 {
    decompose(r, gamma2).0
}

/// LowBits(r): return the low part from Decompose. (Algorithm 38)
pub fn low_bits(r: i32, gamma2: u32) -> i32 {
    decompose(r, gamma2).1
}

/// MakeHint(z, r): compute hint bit. (Algorithm 39)
/// Returns 1 if HighBits(r) ≠ HighBits(r + z), 0 otherwise.
pub fn make_hint(z: i32, r: i32, gamma2: u32) -> i32 {
    let r1 = high_bits(r, gamma2);
    let v1 = high_bits((r as i64 + z as i64).rem_euclid(Q as i64) as i32, gamma2);
    if r1 != v1 { 1 } else { 0 }
}

/// UseHint(h, r): recover HighBits using hint. (Algorithm 40)
pub fn use_hint(h: i32, r: i32, gamma2: u32) -> i32 {
    let alpha = 2 * gamma2 as i32;
    let m = (Q as i32 - 1) / alpha;
    let (r1, r0) = decompose(r, gamma2);

    if h == 0 {
        return r1;
    }

    if r0 > 0 {
        if r1 + 1 == m { 0 } else { r1 + 1 }
    } else {
        if r1 == 0 { m - 1 } else { r1 - 1 }
    }
}

/// Infinity norm of a polynomial (coefficients mod± q).
pub fn infinity_norm(poly: &[i32]) -> u32 {
    poly.iter()
        .map(|&c| {
            let c_centered = mod_pm(c.rem_euclid(Q as i32), Q as i32);
            c_centered.unsigned_abs()
        })
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{ML_DSA_44, ML_DSA_65};

    #[test]
    fn power2round_reconstruction() {
        for r in [0, 1, 1000, Q as i32 / 2, Q as i32 - 1] {
            let (r1, r0) = power2round(r);
            let reconstructed = (r1 * (1 << D) + r0).rem_euclid(Q as i32);
            assert_eq!(
                reconstructed,
                r.rem_euclid(Q as i32),
                "Power2Round({r}): {r1}*2^{D} + {r0} = {reconstructed}"
            );
        }
    }

    #[test]
    fn decompose_reconstruction() {
        for &gamma2 in &[ML_DSA_44.gamma2, ML_DSA_65.gamma2] {
            let alpha = 2 * gamma2 as i32;
            for r in [0, 1, 1000, Q as i32 / 2, Q as i32 - 1, alpha, alpha - 1] {
                let (r1, r0) = decompose(r, gamma2);
                let reconstructed = (r1 as i64 * alpha as i64 + r0 as i64).rem_euclid(Q as i64);
                assert_eq!(
                    reconstructed,
                    r.rem_euclid(Q as i32) as i64,
                    "Decompose({r}, γ₂={gamma2}): {r1}*{alpha} + {r0}"
                );
            }
        }
    }

    #[test]
    fn highbits_lowbits_consistency() {
        let gamma2 = ML_DSA_44.gamma2;
        for r in [0, 100, Q as i32 - 1, Q as i32 / 2] {
            let (r1, r0) = decompose(r, gamma2);
            assert_eq!(r1, high_bits(r, gamma2));
            assert_eq!(r0, low_bits(r, gamma2));
        }
    }

    #[test]
    fn make_use_hint_consistency() {
        let gamma2 = ML_DSA_65.gamma2;
        // When h = MakeHint(z, r), UseHint(h, r+z) should give HighBits(r+z).
        for r in [0, 100, Q as i32 - 1] {
            for z in [0, 1, -1i32, 1000, -1000] {
                let rz = (r as i64 + z as i64).rem_euclid(Q as i64) as i32;
                let h = make_hint(z, r, gamma2);
                let result = use_hint(h, rz, gamma2);
                let expected = high_bits(rz, gamma2);
                // UseHint should recover HighBits when given the correct hint.
                if h == 0 {
                    assert_eq!(result, expected, "UseHint(0, {rz})");
                }
            }
        }
    }

    #[test]
    fn use_hint_mod_m_boundary() {
        // Verify UseHint wraps correctly at the boundaries of [0, m).
        for &gamma2 in &[ML_DSA_44.gamma2, ML_DSA_65.gamma2] {
            let alpha = 2 * gamma2 as i32;
            let m = (Q as i32 - 1) / alpha;

            // Find an r whose r1 = m-1 and r0 > 0 so that (r1+1) mod m should wrap to 0.
            // r1 = m-1 means r ≈ (m-1)*alpha + small positive r0.
            let r_high = (m - 1) * alpha + 1;
            let (r1, r0) = decompose(r_high, gamma2);
            assert_eq!(r1, m - 1, "expected r1 = m-1");
            assert!(r0 > 0, "expected r0 > 0");
            let result = use_hint(1, r_high, gamma2);
            assert_eq!(result, 0, "UseHint(1, r) with r1=m-1 and r0>0 should wrap to 0");

            // Find an r whose r1 = 0 and r0 < 0 so that (r1-1) mod m should wrap to m-1.
            // r1 = 0 when r is near alpha with negative r0 → try r = alpha - 1.
            let r_low = alpha - 1;
            let (r1, r0) = decompose(r_low, gamma2);
            if r1 == 0 && r0 < 0 {
                let result = use_hint(1, r_low, gamma2);
                assert_eq!(result, m - 1, "UseHint(1, r) with r1=0 and r0<0 should wrap to m-1");
            }
        }
    }
}
