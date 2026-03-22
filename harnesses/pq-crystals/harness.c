/*
 * Crucible ML-KEM Harness for pq-crystals/kyber reference implementation
 *
 * This harness wraps the pq-crystals Kyber reference implementation
 * which implements the original Kyber (pre-FIPS 203) KEM.
 *
 * Note: pq-crystals/kyber uses KYBER_K=2/3/4 for 512/768/1024 param sets.
 * We compile three separate object files for each param set and link them
 * with appropriate prefixes to avoid symbol collisions.
 *
 * For simplicity, we compile this harness against KYBER_K=3 (768) only
 * and use the derand variants.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "cJSON.h"

/* pq-crystals Kyber API - we use the api.h names */
#include "api.h"

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

static int hex_decode(const char *hex, uint8_t *out, size_t max_len, size_t *out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > max_len) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + 2*i, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    *out_len = hex_len / 2;
    return 0;
}

static const char *get_input_str(cJSON *inputs, const char *key) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(inputs, key);
    if (!item || !cJSON_IsString(item)) return NULL;
    return item->valuestring;
}

static int get_param_int(cJSON *params, const char *key, int default_val) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(params, key);
    if (!item || !cJSON_IsNumber(item)) return default_val;
    return item->valueint;
}

static void send_json(cJSON *json) {
    char *str = cJSON_PrintUnformatted(json);
    if (str) {
        printf("%s\n", str);
        fflush(stdout);
        free(str);
    }
    cJSON_Delete(json);
}

static void send_error(const char *msg) {
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "error", msg);
    send_json(resp);
}

static void send_unsupported(void) {
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "unsupported", 1);
    send_json(resp);
}

/* Sizes for Kyber-768 */
#define K768_PK  pqcrystals_kyber768_PUBLICKEYBYTES   /* 1184 */
#define K768_SK  pqcrystals_kyber768_SECRETKEYBYTES   /* 2400 */
#define K768_CT  pqcrystals_kyber768_CIPHERTEXTBYTES  /* 1088 */
#define K768_SS  pqcrystals_kyber768_BYTES            /* 32 */
#define K768_COINS pqcrystals_kyber768_KEYPAIRCOINBYTES /* 64 */
#define K768_ENCCOINS pqcrystals_kyber768_ENCCOINBYTES  /* 32 */

static void handle_keygen(cJSON *inputs, cJSON *params) {
    int param_set = get_param_int(params, "param_set", 768);

    if (param_set != 768) {
        send_error("only param_set=768 supported in this build");
        return;
    }

    uint8_t pk[K768_PK], sk[K768_SK];
    const char *rand_hex = get_input_str(inputs, "randomness");
    int rc;

    if (rand_hex) {
        uint8_t coins[64];
        size_t coins_len;
        if (hex_decode(rand_hex, coins, sizeof(coins), &coins_len) != 0 || coins_len != 64) {
            send_error("randomness must be 64 bytes hex");
            return;
        }
        rc = pqcrystals_kyber768_ref_keypair_derand(pk, sk, coins);
    } else {
        rc = pqcrystals_kyber768_ref_keypair(pk, sk);
    }

    if (rc != 0) {
        send_error("keypair failed");
        return;
    }

    char pk_hex[K768_PK * 2 + 1], sk_hex[K768_SK * 2 + 1];
    hex_encode(pk, K768_PK, pk_hex);
    hex_encode(sk, K768_SK, sk_hex);

    cJSON *resp = cJSON_CreateObject();
    cJSON *outputs = cJSON_CreateObject();
    cJSON_AddStringToObject(outputs, "ek", pk_hex);
    cJSON_AddStringToObject(outputs, "dk", sk_hex);
    cJSON_AddItemToObject(resp, "outputs", outputs);
    send_json(resp);
}

static void handle_encaps(cJSON *inputs, cJSON *params) {
    (void)params;

    const char *ek_hex = get_input_str(inputs, "ek");
    if (!ek_hex) {
        send_error("missing input 'ek'");
        return;
    }

    uint8_t pk[K768_PK];
    size_t pk_len;
    if (hex_decode(ek_hex, pk, sizeof(pk), &pk_len) != 0 || pk_len != K768_PK) {
        send_error("invalid ek length");
        return;
    }

    uint8_t ct[K768_CT], ss[K768_SS];
    int rc;

    const char *rand_hex = get_input_str(inputs, "randomness");
    if (rand_hex) {
        uint8_t coins[32];
        size_t coins_len;
        if (hex_decode(rand_hex, coins, sizeof(coins), &coins_len) != 0 || coins_len != 32) {
            send_error("randomness must be 32 bytes hex");
            return;
        }
        rc = pqcrystals_kyber768_ref_enc_derand(ct, ss, pk, coins);
    } else {
        rc = pqcrystals_kyber768_ref_enc(ct, ss, pk);
    }

    if (rc != 0) {
        send_error("encapsulation failed");
        return;
    }

    char ct_hex[K768_CT * 2 + 1], ss_hex[K768_SS * 2 + 1];
    hex_encode(ct, K768_CT, ct_hex);
    hex_encode(ss, K768_SS, ss_hex);

    cJSON *resp = cJSON_CreateObject();
    cJSON *outputs = cJSON_CreateObject();
    cJSON_AddStringToObject(outputs, "c", ct_hex);
    cJSON_AddStringToObject(outputs, "K", ss_hex);
    cJSON_AddItemToObject(resp, "outputs", outputs);
    send_json(resp);
}

static void handle_decaps(cJSON *inputs, cJSON *params) {
    (void)params;

    const char *c_hex = get_input_str(inputs, "c");
    const char *dk_hex = get_input_str(inputs, "dk");
    if (!c_hex) { send_error("missing input 'c'"); return; }
    if (!dk_hex) { send_error("missing input 'dk'"); return; }

    uint8_t ct[K768_CT], sk[K768_SK];
    size_t ct_len, sk_len;
    if (hex_decode(c_hex, ct, sizeof(ct), &ct_len) != 0 || ct_len != K768_CT) {
        send_error("invalid ciphertext length");
        return;
    }
    if (hex_decode(dk_hex, sk, sizeof(sk), &sk_len) != 0 || sk_len != K768_SK) {
        send_error("invalid dk length");
        return;
    }

    uint8_t ss[K768_SS];
    int rc = pqcrystals_kyber768_ref_dec(ss, ct, sk);
    if (rc != 0) {
        send_error("decapsulation failed");
        return;
    }

    char ss_hex[K768_SS * 2 + 1];
    hex_encode(ss, K768_SS, ss_hex);

    cJSON *resp = cJSON_CreateObject();
    cJSON *outputs = cJSON_CreateObject();
    cJSON_AddStringToObject(outputs, "K", ss_hex);
    cJSON_AddItemToObject(resp, "outputs", outputs);
    send_json(resp);
}

int main(void) {
    /* Handshake */
    cJSON *hs = cJSON_CreateObject();
    cJSON_AddStringToObject(hs, "implementation", "pq-crystals-kyber-ref");
    cJSON *funcs = cJSON_CreateArray();
    cJSON_AddItemToArray(funcs, cJSON_CreateString("ML_KEM_KeyGen"));
    cJSON_AddItemToArray(funcs, cJSON_CreateString("ML_KEM_Encaps"));
    cJSON_AddItemToArray(funcs, cJSON_CreateString("ML_KEM_Decaps"));
    cJSON_AddItemToObject(hs, "functions", funcs);
    send_json(hs);

    /* Main loop */
    while (fgets(line_buf, sizeof(line_buf), stdin) != NULL) {
        size_t len = strlen(line_buf);
        if (len > 0 && line_buf[len-1] == '\n') line_buf[--len] = '\0';
        if (len == 0) break;

        cJSON *req = cJSON_Parse(line_buf);
        if (!req) {
            send_error("invalid JSON");
            continue;
        }

        cJSON *func = cJSON_GetObjectItemCaseSensitive(req, "function");
        cJSON *inputs = cJSON_GetObjectItemCaseSensitive(req, "inputs");
        cJSON *params = cJSON_GetObjectItemCaseSensitive(req, "params");

        if (!func || !cJSON_IsString(func)) {
            send_error("missing 'function' field");
            cJSON_Delete(req);
            continue;
        }

        if (!inputs) inputs = cJSON_CreateObject();
        if (!params) params = cJSON_CreateObject();

        const char *fn = func->valuestring;
        if (strcmp(fn, "ML_KEM_KeyGen") == 0) {
            handle_keygen(inputs, params);
        } else if (strcmp(fn, "ML_KEM_Encaps") == 0) {
            handle_encaps(inputs, params);
        } else if (strcmp(fn, "ML_KEM_Decaps") == 0) {
            handle_decaps(inputs, params);
        } else {
            send_unsupported();
        }

        cJSON_Delete(req);
    }

    return 0;
}
