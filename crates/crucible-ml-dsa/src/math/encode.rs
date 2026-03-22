//! Key and signature encoding/decoding per FIPS 204 §7.1–§7.2.
//! Algorithms 9–28.

use crate::params::{MlDsaParams, D, N, Q};

/// SimpleBitPack: encode polynomial with coefficients in [0, b]. (Algorithm 16)
pub fn simple_bit_pack(w: &[i32; N], b: u32) -> Vec<u8> {
    let c = bit_length(b);
    let mut bits = Vec::with_capacity(N * c);
    for i in 0..N {
        let val = w[i] as u32;
        for j in 0..c {
            bits.push(((val >> j) & 1) as u8);
        }
    }
    bits_to_bytes(&bits)
}

/// BitPack: encode polynomial with coefficients in [-a, b]. (Algorithm 17)
pub fn bit_pack(w: &[i32; N], a: u32, b: u32) -> Vec<u8> {
    let c = bit_length(a + b);
    let mut bits = Vec::with_capacity(N * c);
    for i in 0..N {
        let val = (b as i32 - w[i]) as u32;
        for j in 0..c {
            bits.push(((val >> j) & 1) as u8);
        }
    }
    bits_to_bytes(&bits)
}

/// SimpleBitUnpack: decode bytes to polynomial with coefficients in [0, 2^c-1]. (Algorithm 18)
pub fn simple_bit_unpack(v: &[u8], b: u32) -> [i32; N] {
    let c = bit_length(b);
    let bits = bytes_to_bits(v);
    let mut w = [0i32; N];
    for i in 0..N {
        let mut val = 0u32;
        for j in (0..c).rev() {
            val = 2 * val + bits[i * c + j] as u32;
        }
        w[i] = val as i32;
    }
    w
}

/// BitUnpack: decode bytes to polynomial with coefficients in [b-2^c+1, b]. (Algorithm 19)
pub fn bit_unpack(v: &[u8], a: u32, b: u32) -> [i32; N] {
    let c = bit_length(a + b);
    let bits = bytes_to_bits(v);
    let mut w = [0i32; N];
    for i in 0..N {
        let mut val = 0u32;
        for j in (0..c).rev() {
            val = 2 * val + bits[i * c + j] as u32;
        }
        w[i] = b as i32 - val as i32;
    }
    w
}

/// HintBitPack: encode hint vector h. (Algorithm 20)
pub fn hint_bit_pack(h: &[Vec<i32>], omega: usize, k: usize) -> Vec<u8> {
    let mut y = vec![0u8; omega + k];
    let mut index = 0;
    for i in 0..k {
        for j in 0..N {
            if h[i][j] != 0 {
                y[index] = j as u8;
                index += 1;
            }
        }
        y[omega + i] = index as u8;
    }
    y
}

/// HintBitUnpack: decode hint from bytes. (Algorithm 21)
/// Returns None if malformed.
pub fn hint_bit_unpack(y: &[u8], omega: usize, k: usize) -> Option<Vec<Vec<i32>>> {
    if y.len() != omega + k {
        return None;
    }
    let mut h = vec![vec![0i32; N]; k];
    let mut index = 0usize;

    for i in 0..k {
        let end = y[omega + i] as usize;
        if end < index || end > omega {
            return None;
        }
        let first = index;
        while index < end {
            if index > first && y[index - 1] >= y[index] {
                return None; // non-increasing
            }
            let coeff_idx = y[index] as usize;
            if coeff_idx >= N {
                return None;
            }
            h[i][coeff_idx] = 1;
            index += 1;
        }
    }

    // Leftover bytes must be zero.
    for i in index..omega {
        if y[i] != 0 {
            return None;
        }
    }

    Some(h)
}

/// pkEncode (Algorithm 22)
pub fn pk_encode(rho: &[u8; 32], t1: &[[i32; N]], params: &MlDsaParams) -> Vec<u8> {
    let bitlen_q_minus_d = bit_length(Q - 1) - D as usize;
    let b = (1u32 << bitlen_q_minus_d) - 1;
    let mut pk = Vec::from(rho.as_slice());
    for i in 0..params.k {
        pk.extend_from_slice(&simple_bit_pack(&t1[i], b));
    }
    pk
}

/// skEncode (Algorithm 24)
pub fn sk_encode(
    rho: &[u8; 32],
    k_seed: &[u8; 32],
    tr: &[u8; 64],
    s1: &[[i32; N]],
    s2: &[[i32; N]],
    t0: &[[i32; N]],
    params: &MlDsaParams,
) -> Vec<u8> {
    let eta = params.eta;
    let mut sk = Vec::new();
    sk.extend_from_slice(rho);
    sk.extend_from_slice(k_seed);
    sk.extend_from_slice(tr);
    for i in 0..params.l {
        sk.extend_from_slice(&bit_pack(&s1[i], eta, eta));
    }
    for i in 0..params.k {
        sk.extend_from_slice(&bit_pack(&s2[i], eta, eta));
    }
    for i in 0..params.k {
        sk.extend_from_slice(&bit_pack(&t0[i], (1 << (D - 1)) - 1, 1 << (D - 1)));
    }
    sk
}

/// w1Encode (Algorithm 28)
pub fn w1_encode(w1: &[[i32; N]], params: &MlDsaParams) -> Vec<u8> {
    let gamma2 = params.gamma2;
    let b = ((Q - 1) / (2 * gamma2)) - 1;
    let mut encoded = Vec::new();
    for i in 0..params.k {
        encoded.extend_from_slice(&simple_bit_pack(&w1[i], b));
    }
    encoded
}

/// sigEncode (Algorithm 26)
pub fn sig_encode(
    c_tilde: &[u8],
    z: &[[i32; N]],
    h: &[Vec<i32>],
    params: &MlDsaParams,
) -> Vec<u8> {
    let gamma1 = params.gamma1;
    let mut sigma = Vec::from(c_tilde);
    for i in 0..params.l {
        sigma.extend_from_slice(&bit_pack(&z[i], gamma1 - 1, gamma1));
    }
    sigma.extend_from_slice(&hint_bit_pack(h, params.omega, params.k));
    sigma
}

// ---- Helpers ----

fn bit_length(a: u32) -> usize {
    if a == 0 { return 1; }
    32 - a.leading_zeros() as usize
}

fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    let byte_len = (bits.len() + 7) / 8;
    let mut bytes = vec![0u8; byte_len];
    for (i, &bit) in bits.iter().enumerate() {
        bytes[i / 8] |= bit << (i % 8);
    }
    bytes
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hint_bit_pack_unpack_round_trip() {
        let k = 4;
        let omega = 80;
        let mut h = vec![vec![0i32; N]; k];
        h[0][0] = 1;
        h[0][10] = 1;
        h[1][255] = 1;

        let packed = hint_bit_pack(&h, omega, k);
        let unpacked = hint_bit_unpack(&packed, omega, k).unwrap();
        assert_eq!(h, unpacked);
    }

    #[test]
    fn hint_bit_unpack_rejects_malformed() {
        let omega = 80;
        let k = 4;

        // Index out of order.
        let mut y = vec![0u8; omega + k];
        y[0] = 10;
        y[1] = 5; // not increasing
        y[omega] = 2;
        assert!(hint_bit_unpack(&y, omega, k).is_none());
    }

    #[test]
    fn simple_bit_pack_unpack_round_trip() {
        let mut w = [0i32; N];
        w[0] = 0;
        w[1] = 7;
        w[255] = 15;

        let packed = simple_bit_pack(&w, 15);
        let unpacked = simple_bit_unpack(&packed, 15);
        assert_eq!(w, unpacked);
    }
}
