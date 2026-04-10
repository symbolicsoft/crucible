/*
 * Crucible ML-KEM Harness Template — C
 *
 * Wire your ML-KEM implementation to Crucible's test battery.
 * Reference: FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism
 *            (https://doi.org/10.6028/NIST.FIPS.203)
 *
 * Build: cc -O2 -o harness-yourname template.c -ljson-c  (or use cJSON)
 * Run:   crucible ./harness-yourname --battery ml-kem
 *
 * ## Architecture
 *
 * The battery tests functions at two levels:
 *
 * Low-level (auxiliary algorithms, FIPS 203 section 4):
 *   Compress_d, Decompress_d, ByteEncode_d, ByteDecode_d,
 *   NTT, NTT_inv, MultiplyNTTs, SamplePolyCBD, SampleNTT
 *
 * High-level (internal algorithms, FIPS 203 section 6):
 *   ML_KEM_KeyGen (Alg 16), ML_KEM_Encaps (Alg 17), ML_KEM_Decaps (Alg 18)
 *
 * These are the INTERNAL algorithms, not the external ones (section 7).
 * All randomness is provided as explicit input by the battery.
 *
 * Key/ciphertext sizes (FIPS 203, Table 3):
 *   ML-KEM-512:  ek=800   dk=1632  ct=768   ss=32
 *   ML-KEM-768:  ek=1184  dk=2400  ct=1088  ss=32
 *   ML-KEM-1024: ek=1568  dk=3168  ct=1568  ss=32
 *
 * Constants: n=256, q=3329, zeta=17.
 *
 * This template uses a minimal inline approach. For production use,
 * consider cJSON (https://github.com/DaveGamble/cJSON).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_LINE (1024 * 1024)
#define Q 3329
#define N 256

static char line_buf[MAX_LINE];

/* Hex encode/decode */
static void hex_encode(const uint8_t *data, size_t len, char *out) {
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2*i]   = hex_chars[(data[i] >> 4) & 0xF];
        out[2*i+1] = hex_chars[data[i] & 0xF];
    }
    out[2*len] = '\0';
}

static int hex_decode(const char *hex, uint8_t *out, size_t max_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > max_len) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + 2*i, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return (int)(hex_len / 2);
}

/* ---- Protocol ---- */

static void send_handshake(void) {
    /* TODO: Update implementation name and functions list. */
    printf("{\"implementation\":\"your-c-implementation\","
           "\"functions\":["
           "\"Compress_d\",\"Decompress_d\","
           "\"ByteEncode_d\",\"ByteDecode_d\","
           "\"NTT\",\"NTT_inv\",\"MultiplyNTTs\","
           "\"SamplePolyCBD\",\"SampleNTT\","
           "\"ML_KEM_KeyGen\",\"ML_KEM_Encaps\",\"ML_KEM_Decaps\""
           "]}\n");
    fflush(stdout);
}

static void send_error(const char *msg) {
    printf("{\"error\":\"%s\"}\n", msg);
    fflush(stdout);
}

static void send_unsupported(void) {
    printf("{\"unsupported\":true}\n");
    fflush(stdout);
}

/* ---- Function handlers ----
 *
 * Polynomials are encoded as 512 bytes: 256 coefficients x 2 bytes LE each.
 * Coefficients are in [0, q-1] where q = 3329.
 *
 * TODO: Implement each handler by:
 * 1. Parse inputs from the JSON request (hex-decode byte arrays, read params).
 * 2. Call your ML-KEM implementation's corresponding function.
 * 3. Hex-encode the outputs and print a JSON response line.
 */

/* --- Low-level auxiliary functions --- */

static void handle_compress_d(/* parsed request */) {
    /* FIPS 203 section 4.2.1, Eq 4.7: x -> ceil((2^d / q) * x) mod 2^d
     * Input: "x" (2 bytes LE, coefficient in [0, q-1]), param "d" (1-11).
     * Output: "y" (2 bytes LE, compressed value in [0, 2^d - 1]).
     * MUST use integer arithmetic only (section 3.3).
     */
    send_error("Compress_d not implemented");
}

static void handle_decompress_d(/* parsed request */) {
    /* FIPS 203 section 4.2.1, Eq 4.8: y -> ceil((q / 2^d) * y)
     * Input: "y" (2 bytes LE), param "d" (1-11).
     * Output: "x" (2 bytes LE, decompressed coefficient in [0, q-1]).
     */
    send_error("Decompress_d not implemented");
}

static void handle_byte_encode_d(/* parsed request */) {
    /* FIPS 203, Algorithm 5. Input "F": 512 bytes. Param "d": 1-12.
     * Output "B": 32*d bytes. */
    send_error("ByteEncode_d not implemented");
}

static void handle_byte_decode_d(/* parsed request */) {
    /* FIPS 203, Algorithm 6. Input "B": 32*d bytes. Param "d": 1-12.
     * Output "F": 512 bytes. For d=12: coefficients reduced mod q. */
    send_error("ByteDecode_d not implemented");
}

static void handle_ntt(/* parsed request */) {
    /* FIPS 203, Algorithm 9. Input "f": 512 bytes. Output "f_hat": 512 bytes.
     * Must use zeta=17 with BitRev_7 ordering. */
    send_error("NTT not implemented");
}

static void handle_ntt_inv(/* parsed request */) {
    /* FIPS 203, Algorithm 10. Input "f_hat": 512 bytes. Output "f": 512 bytes.
     * Final multiply by 128^{-1} = 3303 mod q. */
    send_error("NTT_inv not implemented");
}

static void handle_multiply_ntts(/* parsed request */) {
    /* FIPS 203, Algorithm 11. Input "f_hat", "g_hat": 512 bytes each.
     * Output "h_hat": 512 bytes. */
    send_error("MultiplyNTTs not implemented");
}

static void handle_sample_poly_cbd(/* parsed request */) {
    /* FIPS 203, Algorithm 8. Input "B": 64*eta bytes. Param "eta": 2 or 3.
     * Output "f": 512 bytes. Coefficients in [-eta, eta] (mod q). */
    send_error("SamplePolyCBD not implemented");
}

static void handle_sample_ntt(/* parsed request */) {
    /* FIPS 203, Algorithm 7. Input "B": 34 bytes (rho + 2 index bytes).
     * Output "a_hat": 512 bytes. All coefficients < q. */
    send_error("SampleNTT not implemented");
}

/* --- High-level internal algorithms --- */

static void handle_keygen(/* parsed request */) {
    /* FIPS 203 section 6.1, Algorithm 16: ML-KEM.KeyGen_internal(d, z)
     * Input "randomness": 64 bytes (d||z), param "param_set": 512/768/1024.
     * Output "ek" (encapsulation key), "dk" (decapsulation key).
     * dk = dk_PKE || ek || H(ek) || z. Must be deterministic.
     */
    send_error("ML_KEM_KeyGen not implemented");
}

static void handle_encaps(/* parsed request */) {
    /* FIPS 203 section 6.2, Algorithm 17: ML-KEM.Encaps_internal(ek, m)
     * Input "ek" (encapsulation key), "randomness" (32 bytes = message m).
     * Output "c" (ciphertext), "K" (32-byte shared secret).
     * Validate ek first (section 7.2): ByteEncode_12(ByteDecode_12(ek)) == ek.
     */
    send_error("ML_KEM_Encaps not implemented");
}

static void handle_decaps(/* parsed request */) {
    /* FIPS 203 section 6.3, Algorithm 18: ML-KEM.Decaps_internal(dk, c)
     * Input "c" (ciphertext), "dk" (decapsulation key).
     * Output "K" (32-byte shared secret or implicit rejection value).
     * MUST always return 32-byte K -- never error on invalid ciphertexts.
     * Re-encryption comparison MUST be constant-time.
     */
    send_error("ML_KEM_Decaps not implemented");
}

/* ---- Main loop ---- */

int main(void) {
    send_handshake();

    while (fgets(line_buf, sizeof(line_buf), stdin) != NULL) {
        /* Strip newline. */
        size_t len = strlen(line_buf);
        if (len > 0 && line_buf[len-1] == '\n') line_buf[--len] = '\0';
        if (len == 0) break;

        /*
         * TODO: Parse the JSON request to extract:
         *   - "function": string
         *   - "inputs": map of string -> hex string
         *   - "params": map of string -> integer
         *
         * Then dispatch to the appropriate handler.
         * Use cJSON for real implementations:
         *   cJSON *req = cJSON_Parse(line_buf);
         *   const char *func = cJSON_GetObjectItem(req, "function")->valuestring;
         */

        /* Placeholder dispatch — replace with real JSON parsing. */
        if (strstr(line_buf, "\"Compress_d\"")) {
            handle_compress_d();
        } else if (strstr(line_buf, "\"Decompress_d\"")) {
            handle_decompress_d();
        } else if (strstr(line_buf, "\"ByteEncode_d\"")) {
            handle_byte_encode_d();
        } else if (strstr(line_buf, "\"ByteDecode_d\"")) {
            handle_byte_decode_d();
        } else if (strstr(line_buf, "\"NTT_inv\"")) {
            handle_ntt_inv();
        } else if (strstr(line_buf, "\"NTT\"")) {
            handle_ntt();
        } else if (strstr(line_buf, "\"MultiplyNTTs\"")) {
            handle_multiply_ntts();
        } else if (strstr(line_buf, "\"SamplePolyCBD\"")) {
            handle_sample_poly_cbd();
        } else if (strstr(line_buf, "\"SampleNTT\"")) {
            handle_sample_ntt();
        } else if (strstr(line_buf, "\"ML_KEM_KeyGen\"")) {
            handle_keygen();
        } else if (strstr(line_buf, "\"ML_KEM_Encaps\"")) {
            handle_encaps();
        } else if (strstr(line_buf, "\"ML_KEM_Decaps\"")) {
            handle_decaps();
        } else {
            send_unsupported();
        }
    }

    return 0;
}
