/*
 * AWS-LC ML-KEM harness for Crucible
 *
 * Protocol: JSON lines over stdin/stdout
 * - Startup: print handshake JSON with implementation name and function list
 * - Read JSON request lines, write JSON response lines
 * - All byte data is hex-encoded
 *
 * Uses the EVP KEM API with deterministic variants from
 * <openssl/experimental/kem_deterministic_api.h>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/err.h>
#include <openssl/experimental/kem_deterministic_api.h>

#include "cJSON.h"

/* ---------- hex helpers ---------- */

static int hex_to_bytes(const char *hex, uint8_t *out, size_t *out_len) {
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0) return -1;
    size_t blen = hlen / 2;
    for (size_t i = 0; i < blen; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%02x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
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

/* ---------- param_set -> NID ---------- */

static int param_set_to_nid(int param_set) {
    switch (param_set) {
        case 512:  return NID_MLKEM512;
        case 768:  return NID_MLKEM768;
        case 1024: return NID_MLKEM1024;
        default:   return 0;
    }
}

/* Guess param_set from ek (public key) length */
static int nid_from_ek_len(size_t len) {
    /* ML-KEM-512: 800, ML-KEM-768: 1184, ML-KEM-1024: 1568 */
    if (len == 800)  return NID_MLKEM512;
    if (len == 1184) return NID_MLKEM768;
    if (len == 1568) return NID_MLKEM1024;
    return 0;
}

/* Guess param_set from dk (secret key) length */
static int nid_from_dk_len(size_t len) {
    /* ML-KEM-512: 1632, ML-KEM-768: 2400, ML-KEM-1024: 3168 */
    if (len == 1632) return NID_MLKEM512;
    if (len == 2400) return NID_MLKEM768;
    if (len == 3168) return NID_MLKEM1024;
    return 0;
}

/* ---------- ML_KEM_KeyGen ---------- */

static void handle_keygen(cJSON *req) {
    /* Get param_set (default 768) */
    int param_set = 768;
    cJSON *params = cJSON_GetObjectItem(req, "params");
    if (params) {
        cJSON *ps = cJSON_GetObjectItem(params, "param_set");
        if (ps && cJSON_IsNumber(ps)) param_set = ps->valueint;
    }

    int nid = param_set_to_nid(param_set);
    if (!nid) {
        send_error("unsupported param_set");
        return;
    }

    /* Get randomness input (64 bytes = d || z) */
    cJSON *inputs = cJSON_GetObjectItem(req, "inputs");
    const char *rand_hex = NULL;
    if (inputs) {
        cJSON *r = cJSON_GetObjectItem(inputs, "randomness");
        if (r && cJSON_IsString(r)) rand_hex = r->valuestring;
    }

    uint8_t seed[64];
    size_t seed_len = 0;
    int have_seed = 0;
    if (rand_hex) {
        if (hex_to_bytes(rand_hex, seed, &seed_len) == 0 && seed_len == 64) {
            have_seed = 1;
        }
    }

    /* Create key context */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, NULL);
    if (!ctx) { send_error("EVP_PKEY_CTX_new_id failed"); return; }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        send_error("EVP_PKEY_keygen_init failed");
        return;
    }

    if (EVP_PKEY_CTX_kem_set_params(ctx, nid) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        send_error("EVP_PKEY_CTX_kem_set_params failed");
        return;
    }

    EVP_PKEY *pkey = NULL;
    int rc;
    if (have_seed) {
        size_t s_len = 64;
        rc = EVP_PKEY_keygen_deterministic(ctx, &pkey, seed, &s_len);
    } else {
        rc = EVP_PKEY_keygen(ctx, &pkey);
    }

    if (rc <= 0 || !pkey) {
        EVP_PKEY_CTX_free(ctx);
        send_error("keygen failed");
        return;
    }

    /* Extract raw public key */
    size_t pk_len = 0;
    EVP_PKEY_get_raw_public_key(pkey, NULL, &pk_len);
    uint8_t *pk = malloc(pk_len);
    EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len);

    /* Extract raw private key */
    size_t sk_len = 0;
    EVP_PKEY_get_raw_private_key(pkey, NULL, &sk_len);
    uint8_t *sk = malloc(sk_len);
    EVP_PKEY_get_raw_private_key(pkey, sk, &sk_len);

    char *pk_hex = bytes_to_hex(pk, pk_len);
    char *sk_hex = bytes_to_hex(sk, sk_len);

    cJSON *outputs = cJSON_CreateObject();
    cJSON_AddStringToObject(outputs, "ek", pk_hex);
    cJSON_AddStringToObject(outputs, "dk", sk_hex);
    send_outputs(outputs);

    free(pk_hex);
    free(sk_hex);
    free(pk);
    free(sk);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

/* ---------- ML_KEM_Encaps ---------- */

static void handle_encaps(cJSON *req) {
    cJSON *inputs = cJSON_GetObjectItem(req, "inputs");
    if (!inputs) { send_error("missing inputs"); return; }

    cJSON *ek_json = cJSON_GetObjectItem(inputs, "ek");
    if (!ek_json || !cJSON_IsString(ek_json)) { send_error("missing ek"); return; }

    size_t ek_len = strlen(ek_json->valuestring) / 2;
    uint8_t *ek = malloc(ek_len + 1);
    if (hex_to_bytes(ek_json->valuestring, ek, &ek_len) != 0) {
        free(ek);
        send_error("invalid ek hex");
        return;
    }

    int nid = nid_from_ek_len(ek_len);
    if (!nid) {
        free(ek);
        send_error("cannot determine param_set from ek length");
        return;
    }

    /* Get optional randomness for deterministic encaps */
    const char *rand_hex = NULL;
    cJSON *r = cJSON_GetObjectItem(inputs, "randomness");
    if (r && cJSON_IsString(r)) rand_hex = r->valuestring;

    uint8_t enc_seed[32];
    size_t enc_seed_len = 0;
    int have_seed = 0;
    if (rand_hex) {
        if (hex_to_bytes(rand_hex, enc_seed, &enc_seed_len) == 0 && enc_seed_len == 32) {
            have_seed = 1;
        }
    }

    /* Create a PKEY from the raw public key */
    EVP_PKEY *pkey = EVP_PKEY_kem_new_raw_public_key(nid, ek, ek_len);
    if (!pkey) {
        free(ek);
        send_error("EVP_PKEY_kem_new_raw_public_key failed");
        return;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        free(ek);
        send_error("EVP_PKEY_CTX_new failed");
        return;
    }

    /* Get output sizes */
    size_t ct_len = 0, ss_len = 0;
    if (have_seed) {
        size_t s_len = 0;
        EVP_PKEY_encapsulate_deterministic(ctx, NULL, &ct_len, NULL, &ss_len, NULL, &s_len);
    } else {
        EVP_PKEY_encapsulate(ctx, NULL, &ct_len, NULL, &ss_len);
    }

    uint8_t *ct = malloc(ct_len);
    uint8_t *ss = malloc(ss_len);

    int rc;
    if (have_seed) {
        size_t s_len = 32;
        rc = EVP_PKEY_encapsulate_deterministic(ctx, ct, &ct_len, ss, &ss_len, enc_seed, &s_len);
    } else {
        rc = EVP_PKEY_encapsulate(ctx, ct, &ct_len, ss, &ss_len);
    }

    if (rc <= 0) {
        free(ct); free(ss); free(ek);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        send_error("encapsulate failed");
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
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}

/* ---------- ML_KEM_Decaps ---------- */

static void handle_decaps(cJSON *req) {
    cJSON *inputs = cJSON_GetObjectItem(req, "inputs");
    if (!inputs) { send_error("missing inputs"); return; }

    cJSON *c_json = cJSON_GetObjectItem(inputs, "c");
    cJSON *dk_json = cJSON_GetObjectItem(inputs, "dk");
    if (!c_json || !cJSON_IsString(c_json)) { send_error("missing c"); return; }
    if (!dk_json || !cJSON_IsString(dk_json)) { send_error("missing dk"); return; }

    size_t ct_len = strlen(c_json->valuestring) / 2;
    uint8_t *ct = malloc(ct_len + 1);
    if (hex_to_bytes(c_json->valuestring, ct, &ct_len) != 0) {
        free(ct);
        send_error("invalid c hex");
        return;
    }

    size_t dk_len = strlen(dk_json->valuestring) / 2;
    uint8_t *dk = malloc(dk_len + 1);
    if (hex_to_bytes(dk_json->valuestring, dk, &dk_len) != 0) {
        free(ct); free(dk);
        send_error("invalid dk hex");
        return;
    }

    int nid = nid_from_dk_len(dk_len);
    if (!nid) {
        free(ct); free(dk);
        send_error("cannot determine param_set from dk length");
        return;
    }

    /* Create PKEY from secret key */
    EVP_PKEY *pkey = EVP_PKEY_kem_new_raw_secret_key(nid, dk, dk_len);
    if (!pkey) {
        free(ct); free(dk);
        send_error("EVP_PKEY_kem_new_raw_secret_key failed");
        return;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        free(ct); free(dk);
        send_error("EVP_PKEY_CTX_new failed");
        return;
    }

    size_t ss_len = 0;
    EVP_PKEY_decapsulate(ctx, NULL, &ss_len, ct, ct_len);

    uint8_t *ss = malloc(ss_len);
    int rc = EVP_PKEY_decapsulate(ctx, ss, &ss_len, ct, ct_len);
    if (rc <= 0) {
        free(ss); free(ct); free(dk);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        send_error("decapsulate failed");
        return;
    }

    char *ss_hex = bytes_to_hex(ss, ss_len);

    cJSON *outputs = cJSON_CreateObject();
    cJSON_AddStringToObject(outputs, "K", ss_hex);
    send_outputs(outputs);

    free(ss_hex);
    free(ss); free(ct); free(dk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
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
    /* Send handshake */
    cJSON *handshake = cJSON_CreateObject();
    cJSON_AddStringToObject(handshake, "implementation", "aws-lc");
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
        /* Strip trailing newline */
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
        if (strlen(line) == 0) break;
        handle_request(line);
    }

    free(line);
    return 0;
}
