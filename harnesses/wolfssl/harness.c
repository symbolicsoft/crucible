/*
 * wolfSSL/wolfCrypt ML-KEM harness for Crucible
 *
 * Protocol: JSON lines over stdin/stdout
 * - Startup: print handshake JSON with implementation name and function list
 * - Read JSON request lines, write JSON response lines
 * - All byte data is hex-encoded
 *
 * Uses wc_MlKemKey_MakeKeyWithRandom / wc_MlKemKey_EncapsulateWithRandom
 * for deterministic operations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/mlkem.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "cJSON.h"

/* ---------- hex helpers ---------- */

static int hex_to_bytes(const char *hex, uint8_t **out, size_t *out_len) {
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0) return -1;
    size_t blen = hlen / 2;
    *out = malloc(blen);
    if (!*out) return -1;
    for (size_t i = 0; i < blen; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%02x", &byte) != 1) { free(*out); *out = NULL; return -1; }
        (*out)[i] = (uint8_t)byte;
    }
    *out_len = blen;
    return 0;
}

static char *bytes_to_hex(const uint8_t *data, size_t len) {
    char *hex = malloc(len * 2 + 1);
    if (!hex) return NULL;
    for (size_t i = 0; i < len; i++)
        sprintf(hex + 2 * i, "%02x", data[i]);
    hex[len * 2] = '\0';
    return hex;
}

/* ---------- response helpers ---------- */

static void send_error(const char *msg) {
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "error", msg);
    char *s = cJSON_PrintUnformatted(resp);
    printf("%s\n", s);
    fflush(stdout);
    free(s);
    cJSON_Delete(resp);
}

static void send_unsupported(void) {
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "unsupported", 1);
    char *s = cJSON_PrintUnformatted(resp);
    printf("%s\n", s);
    fflush(stdout);
    free(s);
    cJSON_Delete(resp);
}

static void send_outputs(cJSON *outputs) {
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddItemToObject(resp, "outputs", outputs);
    char *s = cJSON_PrintUnformatted(resp);
    printf("%s\n", s);
    fflush(stdout);
    free(s);
    cJSON_Delete(resp);
}

/* ---------- param_set -> wolfSSL type ---------- */

static int param_set_to_type(int param_set) {
    switch (param_set) {
        case 512:  return WC_ML_KEM_512;
        case 768:  return WC_ML_KEM_768;
        case 1024: return WC_ML_KEM_1024;
        default:   return -1;
    }
}

/* Guess param_set from ek (public key) length */
static int type_from_ek_len(size_t len) {
    /* ML-KEM-512: 800, ML-KEM-768: 1184, ML-KEM-1024: 1568 */
    if (len == 800)  return WC_ML_KEM_512;
    if (len == 1184) return WC_ML_KEM_768;
    if (len == 1568) return WC_ML_KEM_1024;
    return -1;
}

/* Guess param_set from dk (secret key) length */
static int type_from_dk_len(size_t len) {
    /* ML-KEM-512: 1632, ML-KEM-768: 2400, ML-KEM-1024: 3168 */
    if (len == 1632) return WC_ML_KEM_512;
    if (len == 2400) return WC_ML_KEM_768;
    if (len == 3168) return WC_ML_KEM_1024;
    return -1;
}

/* ---------- ML_KEM_KeyGen ---------- */

static void handle_keygen(cJSON *req) {
    int param_set = 768;
    cJSON *params = cJSON_GetObjectItem(req, "params");
    if (params) {
        cJSON *ps = cJSON_GetObjectItem(params, "param_set");
        if (ps && cJSON_IsNumber(ps)) param_set = ps->valueint;
    }

    int type = param_set_to_type(param_set);
    if (type < 0) { send_error("unsupported param_set"); return; }

    MlKemKey key;
    int ret = wc_MlKemKey_Init(&key, type, NULL, INVALID_DEVID);
    if (ret != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "wc_MlKemKey_Init failed: %d", ret);
        send_error(buf);
        return;
    }

    /* Get optional deterministic randomness */
    cJSON *inputs = cJSON_GetObjectItem(req, "inputs");
    const char *rand_hex = NULL;
    if (inputs) {
        cJSON *r = cJSON_GetObjectItem(inputs, "randomness");
        if (r && cJSON_IsString(r)) rand_hex = r->valuestring;
    }

    if (rand_hex) {
        uint8_t *seed = NULL;
        size_t seed_len = 0;
        if (hex_to_bytes(rand_hex, &seed, &seed_len) == 0 && seed_len == 64) {
            ret = wc_MlKemKey_MakeKeyWithRandom(&key, seed, (int)seed_len);
        } else {
            /* Fallback to random */
            WC_RNG rng;
            wc_InitRng(&rng);
            ret = wc_MlKemKey_MakeKey(&key, &rng);
            wc_FreeRng(&rng);
        }
        free(seed);
    } else {
        WC_RNG rng;
        wc_InitRng(&rng);
        ret = wc_MlKemKey_MakeKey(&key, &rng);
        wc_FreeRng(&rng);
    }

    if (ret != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "MakeKey failed: %d", ret);
        wc_MlKemKey_Free(&key);
        send_error(buf);
        return;
    }

    /* Get key sizes */
    word32 pk_len = 0, sk_len = 0;
    wc_MlKemKey_PublicKeySize(&key, &pk_len);
    wc_MlKemKey_PrivateKeySize(&key, &sk_len);

    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);

    ret = wc_MlKemKey_EncodePublicKey(&key, pk, pk_len);
    if (ret != 0) {
        free(pk); free(sk); wc_MlKemKey_Free(&key);
        send_error("EncodePublicKey failed");
        return;
    }

    ret = wc_MlKemKey_EncodePrivateKey(&key, sk, sk_len);
    if (ret != 0) {
        free(pk); free(sk); wc_MlKemKey_Free(&key);
        send_error("EncodePrivateKey failed");
        return;
    }

    char *pk_hex = bytes_to_hex(pk, pk_len);
    char *sk_hex = bytes_to_hex(sk, sk_len);

    cJSON *outputs = cJSON_CreateObject();
    cJSON_AddStringToObject(outputs, "ek", pk_hex);
    cJSON_AddStringToObject(outputs, "dk", sk_hex);
    send_outputs(outputs);

    free(pk_hex); free(sk_hex);
    free(pk); free(sk);
    wc_MlKemKey_Free(&key);
}

/* ---------- ML_KEM_Encaps ---------- */

static void handle_encaps(cJSON *req) {
    cJSON *inputs = cJSON_GetObjectItem(req, "inputs");
    if (!inputs) { send_error("missing inputs"); return; }

    cJSON *ek_json = cJSON_GetObjectItem(inputs, "ek");
    if (!ek_json || !cJSON_IsString(ek_json)) { send_error("missing ek"); return; }

    uint8_t *ek = NULL;
    size_t ek_len = 0;
    if (hex_to_bytes(ek_json->valuestring, &ek, &ek_len) != 0) {
        send_error("invalid ek hex"); return;
    }

    int type = type_from_ek_len(ek_len);
    if (type < 0) { free(ek); send_error("cannot determine param_set from ek length"); return; }

    MlKemKey key;
    int ret = wc_MlKemKey_Init(&key, type, NULL, INVALID_DEVID);
    if (ret != 0) { free(ek); send_error("wc_MlKemKey_Init failed"); return; }

    ret = wc_MlKemKey_DecodePublicKey(&key, ek, (word32)ek_len);
    if (ret != 0) {
        free(ek); wc_MlKemKey_Free(&key);
        send_error("DecodePublicKey failed");
        return;
    }

    word32 ct_len = 0, ss_len = 0;
    wc_MlKemKey_CipherTextSize(&key, &ct_len);
    wc_MlKemKey_SharedSecretSize(&key, &ss_len);

    uint8_t *ct = malloc(ct_len);
    uint8_t *ss = malloc(ss_len);

    /* Check for deterministic randomness */
    const char *rand_hex = NULL;
    cJSON *r = cJSON_GetObjectItem(inputs, "randomness");
    if (r && cJSON_IsString(r)) rand_hex = r->valuestring;

    if (rand_hex) {
        uint8_t *seed = NULL;
        size_t seed_len = 0;
        if (hex_to_bytes(rand_hex, &seed, &seed_len) == 0 && seed_len == 32) {
            ret = wc_MlKemKey_EncapsulateWithRandom(&key, ct, ss, seed, (int)seed_len);
        } else {
            WC_RNG rng;
            wc_InitRng(&rng);
            ret = wc_MlKemKey_Encapsulate(&key, ct, ss, &rng);
            wc_FreeRng(&rng);
        }
        free(seed);
    } else {
        WC_RNG rng;
        wc_InitRng(&rng);
        ret = wc_MlKemKey_Encapsulate(&key, ct, ss, &rng);
        wc_FreeRng(&rng);
    }

    if (ret != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "Encapsulate failed: %d", ret);
        free(ct); free(ss); free(ek); wc_MlKemKey_Free(&key);
        send_error(buf);
        return;
    }

    char *ct_hex = bytes_to_hex(ct, ct_len);
    char *ss_hex = bytes_to_hex(ss, ss_len);

    cJSON *outputs = cJSON_CreateObject();
    cJSON_AddStringToObject(outputs, "c", ct_hex);
    cJSON_AddStringToObject(outputs, "K", ss_hex);
    send_outputs(outputs);

    free(ct_hex); free(ss_hex);
    free(ct); free(ss); free(ek);
    wc_MlKemKey_Free(&key);
}

/* ---------- ML_KEM_Decaps ---------- */

static void handle_decaps(cJSON *req) {
    cJSON *inputs = cJSON_GetObjectItem(req, "inputs");
    if (!inputs) { send_error("missing inputs"); return; }

    cJSON *c_json = cJSON_GetObjectItem(inputs, "c");
    cJSON *dk_json = cJSON_GetObjectItem(inputs, "dk");
    if (!c_json || !cJSON_IsString(c_json)) { send_error("missing c"); return; }
    if (!dk_json || !cJSON_IsString(dk_json)) { send_error("missing dk"); return; }

    uint8_t *ct = NULL, *dk = NULL;
    size_t ct_len = 0, dk_len = 0;
    if (hex_to_bytes(c_json->valuestring, &ct, &ct_len) != 0) { send_error("invalid c hex"); return; }
    if (hex_to_bytes(dk_json->valuestring, &dk, &dk_len) != 0) { free(ct); send_error("invalid dk hex"); return; }

    int type = type_from_dk_len(dk_len);
    if (type < 0) { free(ct); free(dk); send_error("cannot determine param_set from dk length"); return; }

    MlKemKey key;
    int ret = wc_MlKemKey_Init(&key, type, NULL, INVALID_DEVID);
    if (ret != 0) { free(ct); free(dk); send_error("wc_MlKemKey_Init failed"); return; }

    ret = wc_MlKemKey_DecodePrivateKey(&key, dk, (word32)dk_len);
    if (ret != 0) {
        free(ct); free(dk); wc_MlKemKey_Free(&key);
        send_error("DecodePrivateKey failed");
        return;
    }

    word32 ss_len = 0;
    wc_MlKemKey_SharedSecretSize(&key, &ss_len);
    uint8_t *ss = malloc(ss_len);

    ret = wc_MlKemKey_Decapsulate(&key, ss, ct, (word32)ct_len);
    if (ret != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "Decapsulate failed: %d", ret);
        free(ss); free(ct); free(dk); wc_MlKemKey_Free(&key);
        send_error(buf);
        return;
    }

    char *ss_hex = bytes_to_hex(ss, ss_len);

    cJSON *outputs = cJSON_CreateObject();
    cJSON_AddStringToObject(outputs, "K", ss_hex);
    send_outputs(outputs);

    free(ss_hex);
    free(ss); free(ct); free(dk);
    wc_MlKemKey_Free(&key);
}

/* ---------- main ---------- */

static void handle_request(const char *line) {
    cJSON *req = cJSON_Parse(line);
    if (!req) { send_error("invalid JSON"); return; }

    cJSON *func = cJSON_GetObjectItem(req, "function");
    if (!func || !cJSON_IsString(func)) {
        cJSON_Delete(req);
        send_error("missing function");
        return;
    }

    const char *fn = func->valuestring;
    if (strcmp(fn, "ML_KEM_KeyGen") == 0) {
        handle_keygen(req);
    } else if (strcmp(fn, "ML_KEM_Encaps") == 0) {
        handle_encaps(req);
    } else if (strcmp(fn, "ML_KEM_Decaps") == 0) {
        handle_decaps(req);
    } else {
        send_unsupported();
    }

    cJSON_Delete(req);
}

int main(void) {
    wolfCrypt_Init();

    /* Send handshake */
    cJSON *handshake = cJSON_CreateObject();
    cJSON_AddStringToObject(handshake, "implementation", "wolfssl");
    cJSON *funcs = cJSON_CreateStringArray(
        (const char *[]){"ML_KEM_KeyGen", "ML_KEM_Encaps", "ML_KEM_Decaps"}, 3);
    cJSON_AddItemToObject(handshake, "functions", funcs);
    char *hs = cJSON_PrintUnformatted(handshake);
    printf("%s\n", hs);
    fflush(stdout);
    free(hs);
    cJSON_Delete(handshake);

    /* Process requests from stdin */
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    while ((len = getline(&line, &cap, stdin)) > 0) {
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
        if (strlen(line) == 0) break;
        handle_request(line);
    }

    free(line);
    wolfCrypt_Cleanup();
    return 0;
}
