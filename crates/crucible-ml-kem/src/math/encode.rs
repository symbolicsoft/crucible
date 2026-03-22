use crate::params::{N, Q};

/// ByteEncode_d: encode 256 integers mod m into 32·d bytes.
/// Per FIPS 203 Algorithm 5.
///
/// For d < 12, m = 2^d. For d = 12, m = q = 3329.
pub fn byte_encode(f: &[u32; N], d: u32) -> Vec<u8> {
    debug_assert!(d >= 1 && d <= 12);

    // First, encode to bits.
    let mut bits = vec![0u8; N * d as usize];
    for i in 0..N {
        let mut a = f[i];
        for j in 0..d as usize {
            bits[i * d as usize + j] = (a & 1) as u8;
            a >>= 1;
        }
    }

    // Convert bits to bytes (little-endian).
    bits_to_bytes(&bits)
}

/// ByteDecode_d: decode 32·d bytes into 256 integers mod m.
/// Per FIPS 203 Algorithm 6.
///
/// For d < 12, m = 2^d. For d = 12, m = q = 3329 (values are reduced mod q).
pub fn byte_decode(b: &[u8], d: u32) -> [u32; N] {
    debug_assert!(d >= 1 && d <= 12);
    debug_assert_eq!(b.len(), 32 * d as usize);

    let bits = bytes_to_bits(b);
    let m = if d < 12 { 1u32 << d } else { Q };

    let mut f = [0u32; N];
    for i in 0..N {
        let mut val = 0u32;
        for j in (0..d as usize).rev() {
            val = 2 * val + bits[i * d as usize + j] as u32;
        }
        f[i] = val % m;
    }
    f
}

/// BitsToBytes: convert a bit array (length multiple of 8) to bytes.
/// Per FIPS 203 Algorithm 3.
fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    let byte_len = (bits.len() + 7) / 8;
    let mut bytes = vec![0u8; byte_len];
    for (i, &bit) in bits.iter().enumerate() {
        bytes[i / 8] |= bit << (i % 8);
    }
    bytes
}

/// BytesToBits: convert bytes to a bit array.
/// Per FIPS 203 Algorithm 4.
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

/// Check the encapsulation key modulus check:
/// ByteEncode_12(ByteDecode_12(ek)) == ek
/// Returns true if the key passes (all 12-bit values are < q).
pub fn ek_modulus_check(ek_pke: &[u8]) -> bool {
    // ek_pke should be a multiple of 384 bytes (= 32 * 12).
    if ek_pke.len() % 384 != 0 {
        return false;
    }

    for chunk in ek_pke.chunks(384) {
        let decoded = byte_decode(chunk, 12);
        let re_encoded = byte_encode(&decoded, 12);
        if chunk != re_encoded.as_slice() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        for d in 1..=12u32 {
            let m = if d < 12 { 1u32 << d } else { Q };
            // Test with all-zeros.
            let f = [0u32; N];
            let encoded = byte_encode(&f, d);
            let decoded = byte_decode(&encoded, d);
            assert_eq!(f, decoded, "round-trip failed for d={d} all-zeros");

            // Test with max values.
            let f_max = [m - 1; N];
            let encoded = byte_encode(&f_max, d);
            let decoded = byte_decode(&encoded, d);
            assert_eq!(f_max, decoded, "round-trip failed for d={d} all-max");

            // Test with ascending values.
            let mut f_asc = [0u32; N];
            for i in 0..N {
                f_asc[i] = (i as u32) % m;
            }
            let encoded = byte_encode(&f_asc, d);
            let decoded = byte_decode(&encoded, d);
            assert_eq!(f_asc, decoded, "round-trip failed for d={d} ascending");
        }
    }

    #[test]
    fn byte_decode_12_reduces_mod_q() {
        // Construct a 384-byte array where the first 12-bit value is 3329 (= q).
        // 3329 in 12-bit LE: bits are 3329 = 0b110100000001
        // As bits: [1,0,0,0,0,0,0,0,1,0,1,1] (little-endian)
        // First byte = bits 0-7 = 0b00000001 = 1
        // Bits 8-11 of first value + bits 0-3 of second value = 0b1101_0000 = 0xD0
        // Actually let's just construct it properly:
        let mut f = [0u32; N];
        f[0] = 3329; // This is >= q, so ByteEncode would never produce it,
                      // but ByteDecode should reduce it mod q to 0.
        // We can't use byte_encode for this because it assumes values < m.
        // Instead, manually create the byte stream.
        let mut bits = vec![0u8; N * 12];
        for i in 0..N {
            let mut a = f[i];
            for j in 0..12 {
                bits[i * 12 + j] = (a & 1) as u8;
                a >>= 1;
            }
        }
        let bytes = super::bits_to_bytes(&bits);
        let decoded = byte_decode(&bytes, 12);
        assert_eq!(decoded[0], 0, "3329 should decode to 0 mod q");

        // Test 4095 (max 12-bit value).
        f[0] = 4095;
        let mut bits2 = vec![0u8; N * 12];
        for i in 0..N {
            let mut a = f[i];
            for j in 0..12 {
                bits2[i * 12 + j] = (a & 1) as u8;
                a >>= 1;
            }
        }
        let bytes2 = super::bits_to_bytes(&bits2);
        let decoded2 = byte_decode(&bytes2, 12);
        assert_eq!(decoded2[0], 4095 % Q, "4095 should decode to {} mod q", 4095 % Q);
    }
}
