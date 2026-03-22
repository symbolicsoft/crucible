use crate::params::{N, Q};

/// SamplePolyCBD_η: sample polynomial from centered binomial distribution.
/// Per FIPS 203 Algorithm 8.
///
/// Input: byte array B of length 64·η.
/// Output: array f ∈ ℤ_q^256.
///
/// Each coefficient is x - y where x, y ∈ {0, ..., η} are sums of η bits each.
pub fn sample_poly_cbd(b: &[u8], eta: usize) -> [u32; N] {
    assert_eq!(b.len(), 64 * eta);

    let bits = bytes_to_bits(b);
    let mut f = [0u32; N];

    for i in 0..N {
        let mut x = 0u32;
        for j in 0..eta {
            x += bits[2 * i * eta + j] as u32;
        }
        let mut y = 0u32;
        for j in 0..eta {
            y += bits[2 * i * eta + eta + j] as u32;
        }
        // f[i] = (x - y) mod q
        f[i] = ((x as i32 - y as i32).rem_euclid(Q as i32)) as u32;
    }

    f
}

/// SampleNTT: rejection-sample an element of T_q from a seed.
/// Per FIPS 203 Algorithm 7.
///
/// This takes a raw byte stream (XOF output) and produces coefficients.
/// In a real implementation, the XOF would be SHAKE128 seeded with the input.
/// Here we take pre-expanded bytes for testing purposes.
pub fn sample_ntt_from_bytes(xof_bytes: &[u8]) -> Result<[u32; N], &'static str> {
    let mut a_hat = [0u32; N];
    let mut j = 0usize;
    let mut byte_idx = 0;

    while j < N {
        if byte_idx + 3 > xof_bytes.len() {
            return Err("insufficient XOF bytes for SampleNTT");
        }
        let c0 = xof_bytes[byte_idx] as u32;
        let c1 = xof_bytes[byte_idx + 1] as u32;
        let c2 = xof_bytes[byte_idx + 2] as u32;
        byte_idx += 3;

        let d1 = c0 + 256 * (c1 % 16);
        let d2 = (c1 / 16) + 16 * c2;

        if d1 < Q {
            a_hat[j] = d1;
            j += 1;
        }
        if d2 < Q && j < N {
            a_hat[j] = d2;
            j += 1;
        }
    }

    Ok(a_hat)
}

fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = vec![0u8; bytes.len() * 8];
    for i in 0..bytes.len() {
        let mut c = bytes[i];
        for j in 0..8 {
            bits[8 * i + j] = c & 1;
            c >>= 1;
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbd_output_range() {
        // With eta=2, each coefficient should be in {0, 1, 2, q-2, q-1} = {0,1,2,3327,3328}.
        let b = vec![0u8; 128]; // 64 * 2
        let f = sample_poly_cbd(&b, 2);
        for &coeff in &f {
            assert!(coeff < Q);
        }
    }

    #[test]
    fn cbd_all_zeros_gives_all_zeros() {
        let b = vec![0u8; 128];
        let f = sample_poly_cbd(&b, 2);
        for &coeff in &f {
            assert_eq!(coeff, 0, "all-zero input should give all-zero coefficients");
        }
    }

    #[test]
    fn cbd_eta3_range() {
        // With eta=3, coefficients in {0,1,2,3, q-3,q-2,q-1}.
        let b = vec![0xFFu8; 192]; // 64 * 3, all ones
        let f = sample_poly_cbd(&b, 3);
        for &coeff in &f {
            // x = 3, y = 3, so x - y = 0
            assert_eq!(coeff, 0);
        }
    }

    #[test]
    fn sample_ntt_rejects_above_q() {
        // All 0xFF bytes: d1 = 255 + 256*15 = 4095, d2 = 15 + 16*255 = 4095.
        // Both >= q = 3329, so all rejected.
        let xof_bytes = vec![0xFF; 3 * 256]; // not enough accepted values
        let result = sample_ntt_from_bytes(&xof_bytes);
        assert!(result.is_err(), "should fail with all-rejected bytes");
    }

    #[test]
    fn sample_ntt_accepts_below_q() {
        // Construct bytes that always produce d1 = 0, d2 = 0.
        // c0 = 0, c1 = 0, c2 = 0 → d1 = 0, d2 = 0
        let xof_bytes = vec![0u8; 3 * 128]; // 128 triplets → 256 coefficients (2 per triplet)
        let result = sample_ntt_from_bytes(&xof_bytes).unwrap();
        for &coeff in &result {
            assert_eq!(coeff, 0);
        }
    }
}
