/*
 * Crucible ML-KEM Harness Template — C
 *
 * Fill in the TODO sections to wire your ML-KEM implementation to Crucible.
 * Each function receives hex-decoded byte inputs and returns hex-encoded outputs.
 *
 * Build: cc -O2 -o harness-yourname template.c -ljson-c  (or use cJSON, etc.)
 * Run:   crucible ./harness-yourname
 *
 * This template uses a minimal inline JSON parser to avoid external dependencies.
 * For production use, consider cJSON (https://github.com/DaveGamble/cJSON).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---- Minimal JSON helpers (replace with cJSON for production) ---- */

/* You'll need a JSON library. This template shows the protocol structure. */
/* For a real harness, use cJSON or json-c. */

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
           "\"functions\":[\"Compress_d\",\"Decompress_d\","
           "\"ML_KEM_KeyGen\",\"ML_KEM_Encaps\",\"ML_KEM_Decaps\"]}\n");
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

/* ---- Function handlers ---- */

/*
 * Polynomials are encoded as 512 bytes: 256 coefficients x 2 bytes LE each.
 * Coefficients are in [0, q-1] where q = 3329.
 *
 * TODO: Implement each handler by:
 * 1. Parse inputs from the JSON request (hex-decode byte arrays, read params).
 * 2. Call your ML-KEM implementation's corresponding function.
 * 3. Hex-encode the outputs and print a JSON response line.
 */

static void handle_compress_d(/* parsed request */) {
    /* Input: "x" (2 bytes LE, coefficient), param "d" (1-11).
     * Output: "y" (2 bytes LE, compressed value).
     *
     * TODO: uint32_t y = your_compress(x, d);
     */
    send_error("Compress_d not implemented");
}

static void handle_decompress_d(/* parsed request */) {
    /* Input: "y" (2 bytes LE), param "d" (1-11).
     * Output: "x" (2 bytes LE).
     */
    send_error("Decompress_d not implemented");
}

static void handle_keygen(/* parsed request */) {
    /* Input: "randomness" (64 bytes = d||z), param "param_set" (512/768/1024).
     * Output: "ek" (encapsulation key), "dk" (decapsulation key).
     */
    send_error("ML_KEM_KeyGen not implemented");
}

static void handle_encaps(/* parsed request */) {
    /* Input: "ek" (encapsulation key), "randomness" (32 bytes).
     * Output: "c" (ciphertext), "K" (32-byte shared secret).
     */
    send_error("ML_KEM_Encaps not implemented");
}

static void handle_decaps(/* parsed request */) {
    /* Input: "c" (ciphertext), "dk" (decapsulation key).
     * Output: "K" (32-byte shared secret or implicit rejection value).
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
