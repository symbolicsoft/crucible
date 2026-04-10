/*
 * Crucible ML-DSA Harness Template — C
 *
 * Wire your ML-DSA implementation to Crucible's test battery.
 * Reference: FIPS 204, Module-Lattice-Based Digital Signature Standard
 *            (https://doi.org/10.6028/NIST.FIPS.204)
 *
 * Build: cc -O2 -o harness-yourname template-ml-dsa.c -ljson-c  (or use cJSON)
 * Run:   crucible ./harness-yourname --battery ml-dsa
 *
 * ## Architecture
 *
 * This harness targets the INTERNAL algorithms from FIPS 204 section 6:
 *   - ML_DSA_KeyGen  -> Algorithm 6  (ML-DSA.KeyGen_internal)
 *   - ML_DSA_Sign    -> Algorithm 7  (ML-DSA.Sign_internal)
 *   - ML_DSA_Verify  -> Algorithm 8  (ML-DSA.Verify_internal)
 *
 * NOT the external algorithms (section 5, Algorithms 1-3), which add
 * randomness generation and domain-separated message encoding.
 *
 * The "message" input sent by Crucible is the pre-formatted message
 * representative M' (a byte string passed directly to Sign_internal /
 * Verify_internal). It is NOT the raw application message M.
 *
 * If your library only exposes the external API (with a context string),
 * you can bridge to it: for "pure" ML-DSA with an empty context, the
 * external Sign/Verify prepend a 2-byte header (0x00 || 0x00) to M before
 * passing it to the internal function as M'. So you would need to strip
 * that 2-byte prefix from the "message" input to recover the raw M, then
 * call your external API with ctx = "" (the empty string). However, it is
 * preferable to call the internal API directly when possible.
 *
 * This template uses a minimal inline JSON approach. For production use,
 * consider cJSON (https://github.com/DaveGamble/cJSON).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_LINE (1024 * 1024)

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
    /* TODO: Update implementation name. */
    printf("{\"implementation\":\"your-c-implementation\","
           "\"functions\":[\"ML_DSA_KeyGen\",\"ML_DSA_Sign\",\"ML_DSA_Verify\"]}\n");
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
 * Key/signature byte sizes per parameter set (FIPS 204, Table 2):
 *
 *   Parameter set   pk bytes   sk bytes   sig bytes
 *   ML-DSA-44       1312       2560       2420
 *   ML-DSA-65       1952       4032       3309
 *   ML-DSA-87       2592       4896       4627
 */

static void handle_keygen(/* parsed request */) {
    /* FIPS 204 section 6.1, Algorithm 6: ML-DSA.KeyGen_internal(xi)
     *
     * Input "seed": 32 bytes (xi, the key-generation seed).
     * Param "param_set": 44, 65, or 87.
     * Output "pk": public key bytes, "sk": secret key bytes.
     *
     * This MUST be deterministic: the same xi must always produce
     * the same (pk, sk) pair, exactly matching Algorithm 6.
     *
     * TODO: Extract seed and param_set from JSON, call your KeyGen_internal,
     *       then respond:
     *   printf("{\"outputs\":{\"pk\":\"%s\",\"sk\":\"%s\"}}\n", pk_hex, sk_hex);
     *   fflush(stdout);
     */
    send_error("ML_DSA_KeyGen not implemented");
}

static void handle_sign(/* parsed request */) {
    /* FIPS 204 section 6.2, Algorithm 7: ML-DSA.Sign_internal(sk, M', rnd)
     *
     * Input "sk": secret key bytes (as returned by KeyGen).
     * Input "message": the formatted message M' (byte string).
     *   IMPORTANT: This is M', NOT the raw application message M.
     *   Pass these bytes directly to your Sign_internal. Do NOT apply
     *   any additional domain-separation encoding.
     * Input "rnd": 32 bytes.
     *   - Deterministic signing: rnd = {0}^32 (32 zero bytes).
     *   - Hedged signing: rnd = 32 fresh random bytes.
     * Output "signature": the encoded signature (byte string).
     *
     * The parameter set can be inferred from sk length:
     *   2560 -> ML-DSA-44,  4032 -> ML-DSA-65,  4896 -> ML-DSA-87
     *
     * TODO: Extract sk, message, rnd from JSON, call your Sign_internal,
     *       then respond:
     *   printf("{\"outputs\":{\"signature\":\"%s\"}}\n", sig_hex);
     *   fflush(stdout);
     */
    send_error("ML_DSA_Sign not implemented");
}

static void handle_verify(/* parsed request */) {
    /* FIPS 204 section 6.3, Algorithm 8: ML-DSA.Verify_internal(pk, M', sigma)
     *
     * Input "pk": public key bytes.
     * Input "message": the formatted message M' (byte string).
     *   IMPORTANT: Same as for Sign -- this is M', not the raw message.
     * Input "sigma": the signature (byte string).
     * Output "valid": 1 byte -- "01" if valid, "00" if not.
     *
     * The parameter set can be inferred from pk length:
     *   1312 -> ML-DSA-44,  1952 -> ML-DSA-65,  2592 -> ML-DSA-87
     *
     * Per FIPS 204 section 3.6.2: implementations that accept pk or sigma
     * of non-standard length SHALL return false (not an error).
     * Return "valid" = "00" for malformed input, wrong-length keys/
     * signatures, or invalid signatures -- do NOT return an error
     * response, as the battery tests expect a boolean result.
     *
     * TODO: Extract pk, message, sigma from JSON, call your Verify_internal,
     *       then respond:
     *   printf("{\"outputs\":{\"valid\":\"%s\"}}\n", valid ? "01" : "00");
     *   fflush(stdout);
     */
    send_error("ML_DSA_Verify not implemented");
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
        if (strstr(line_buf, "\"ML_DSA_KeyGen\"")) {
            handle_keygen();
        } else if (strstr(line_buf, "\"ML_DSA_Sign\"")) {
            handle_sign();
        } else if (strstr(line_buf, "\"ML_DSA_Verify\"")) {
            handle_verify();
        } else {
            send_unsupported();
        }
    }

    return 0;
}
