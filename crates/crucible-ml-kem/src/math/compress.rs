use crate::params::Q;

/// Compress_d: ℤ_q → ℤ_{2^d}
/// Compress_d(x) = ⌈(2^d / q) · x⌋ mod 2^d
///
/// Per FIPS 203 §4.2.1, Eq. 4.7. Division and rounding are in the rationals.
/// The tie-breaking rule is ⌈y + 1/2⌋ = y + 1 (round half up).
/// Floating-point shall not be used.
pub fn compress_d(x: u32, d: u32) -> u32 {
    debug_assert!(x < Q);
    debug_assert!(d >= 1 && d <= 11);

    // Compute ⌈(2^d / q) · x⌋ mod 2^d using integer arithmetic.
    // (2^d · x + q/2) / q, where q/2 is integer division (= 1664).
    // This gives correct rounding because:
    //   ⌈r⌋ = floor(r + 0.5) for non-half-integers
    //   ⌈y + 0.5⌋ = y + 1 for the tie-break
    // And (2^d * x) / q + 0.5 = (2^d * x + q/2) / q when q is odd.
    // Since q = 3329 is odd, q/2 = 1664 (floor), and we get:
    //   floor((2^d * x + 1664) / 3329) mod 2^d
    let two_d = 1u64 << d;
    let numerator = (two_d * x as u64) + (Q as u64 / 2);
    let result = (numerator / Q as u64) % two_d;
    result as u32
}

/// Decompress_d: ℤ_{2^d} → ℤ_q
/// Decompress_d(y) = ⌈(q / 2^d) · y⌋
///
/// Per FIPS 203 §4.2.1, Eq. 4.8.
pub fn decompress_d(y: u32, d: u32) -> u32 {
    debug_assert!(y < (1 << d));
    debug_assert!(d >= 1 && d <= 11);

    // ⌈(q / 2^d) · y⌋ = floor((q * y + 2^(d-1)) / 2^d)
    let two_d = 1u64 << d;
    let numerator = Q as u64 * y as u64 + (two_d / 2);
    let result = numerator / two_d;
    result as u32
}

/// Find all coefficient values x ∈ [0, q-1] that sit at rounding boundaries for Compress_d.
/// A rounding boundary is where the rational value (2^d / q) · x is within ε of a half-integer.
/// Returns pairs (x, compressed_value) for values at or near boundaries.
pub fn find_rounding_boundaries(d: u32) -> Vec<(u32, u32)> {
    let mut boundaries = Vec::new();
    let two_d = 1u64 << d;

    for x in 0..Q {
        // Compute 2 * (2^d * x) mod q to detect half-integer proximity.
        // (2^d * x) / q is near a half-integer when 2*(2^d*x) mod (2*q) is near q.
        let double_num = 2 * two_d * x as u64;
        let double_q = 2 * Q as u64;
        let remainder = double_num % double_q;

        // Near a half-integer if remainder is close to q (within 1).
        let dist_to_half = if remainder >= Q as u64 {
            remainder - Q as u64
        } else {
            Q as u64 - remainder
        };

        if dist_to_half <= 1 {
            boundaries.push((x, compress_d(x, d)));
        }
    }
    boundaries
}

/// Compute what IEEE 754 f64 would give for compress_d, to detect float usage.
pub fn compress_d_float(x: u32, d: u32) -> u32 {
    let two_d = (1u64 << d) as f64;
    let result = ((two_d / Q as f64) * x as f64).round() as u64 % (1u64 << d);
    result as u32
}

/// Find values where float and integer implementations diverge.
pub fn find_float_divergences(d: u32) -> Vec<(u32, u32, u32)> {
    let mut divergences = Vec::new();
    for x in 0..Q {
        let correct = compress_d(x, d);
        let float_result = compress_d_float(x, d);
        if correct != float_result {
            divergences.push((x, correct, float_result));
        }
    }
    divergences
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_decompress_identity() {
        // Decompress then Compress preserves input: Compress_d(Decompress_d(y)) = y
        for d in 1..=11u32 {
            for y in 0..(1u32 << d) {
                let decompressed = decompress_d(y, d);
                let recompressed = compress_d(decompressed, d);
                assert_eq!(
                    recompressed, y,
                    "Compress_d(Decompress_d({y})) != {y} for d={d}"
                );
            }
        }
    }

    #[test]
    fn compress_in_range() {
        for d in 1..=11u32 {
            for x in 0..Q {
                let c = compress_d(x, d);
                assert!(c < (1 << d), "Compress_{d}({x}) = {c} out of range");
            }
        }
    }

    #[test]
    fn decompress_in_range() {
        for d in 1..=11u32 {
            for y in 0..(1u32 << d) {
                let x = decompress_d(y, d);
                assert!(x < Q, "Decompress_{d}({y}) = {x} out of range");
            }
        }
    }

    #[test]
    fn compress_boundary_values() {
        // Test specific boundary cases.
        assert_eq!(compress_d(0, 1), 0);
        assert_eq!(compress_d(Q - 1, 1), 0); // 3328 maps close to 2/q * 3328 ≈ 1.9994 ≈ 0 mod 2
        assert_eq!(compress_d(1664, 1), 1); // q/2 ≈ 1664, should map to 1
    }
}
