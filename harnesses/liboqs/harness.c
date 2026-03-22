/*
 * liboqs ML-KEM and ML-DSA harness for Crucible
 *
 * Protocol: JSON lines over stdin/stdout
 * - Startup: print handshake JSON with implementation name and function list
 * - Read JSON request lines, write JSON response lines
 * - All byte data is hex-encoded
 *
 * Supports deterministic keygen/encaps via OQS_KEM_keypair_derand / OQS_KEM_encaps_derand.
 * ML-DSA uses random keygen since OQS doesn't expose derand for signatures.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <oqs/oqs.h>

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

/* ---------- param_set -> OQS alg name ---------- */

static const char *kem_alg_name(int param_set) {
    switch (param_set) {
        case 512:  return OQS_KEM_alg_ml_kem_512;
        case 768:  return OQS_KEM_alg_ml_kem_768;
        case 1024: return OQS_KEM_alg_ml_kem_1024;
        default:   return NULL;
    }
}

/* Guess param_set from ek (public key) length */
static const char *kem_alg_from_ek_len(size_t len) {
    if (len == 800)  return OQS_KEM_alg_ml_kem_512;
    if (len == 1184) return OQS_KEM_alg_ml_kem_768;
    if (len == 1568) return OQS_KEM_alg_ml_kem_1024;
    return NULL;
}

/* Guess param_set from dk (secret key) length */
static const char *kem_alg_from_dk_len(size_t len) {
    if (len == 1632) return OQS_KEM_alg_ml_kem_512;
    if (len == 2400) return OQS_KEM_alg_ml_kem_768;
    if (len == 3168) return OQS_KEM_alg_ml_kem_1024;
    return NULL;
}

/* ML-DSA param_set -> OQS alg name */
static const char *sig_alg_name(int param_set) {
    switch (param_set) {
        case 44: return OQS_SIG_alg_ml_dsa_44;
        case 65: return OQS_SIG_alg_ml_dsa_65;
        case 87: return OQS_SIG_alg_ml_dsa_87;
        default: return NULL;
    }
}

/* Guess ML-DSA param_set from sk length */
static const char *sig_alg_from_sk_len(size_t len) {
    /* ML-DSA-44: sk=2560, ML-DSA-65: sk=4032, ML-DSA-87: sk=4896 */
    if (len == 2560) return OQS_SIG_alg_ml_dsa_44;
    if (len == 4032) return OQS_SIG_alg_ml_dsa_65;
    if (len == 4896) return OQS_SIG_alg_ml_dsa_87;
    return NULL;
}

/* Guess ML-DSA param_set from pk length */
static const char *sig_alg_from_pk_len(size_t len) {
    /* ML-DSA-44: pk=1312, ML-DSA-65: pk=1952, ML-DSA-87: pk=2592 */
    if (len == 1312) return OQS_SIG_alg_ml_dsa_44;
    if (len == 1952) return OQS_SIG_alg_ml_dsa_65;
    if (len == 2592) return OQS_SIG_alg_ml_dsa_87;
    return NULL;
}

/* ---------- ML_KEM_KeyGen ---------- */

static void handle_kem_keygen(cJSON *req) {
    int param_set = 768;
    cJSON *params = cJSON_GetObjectItem(req, "params");
    if (params) {
        cJSON *ps = cJSON_GetObjectItem(params, "param_set");
        if (ps && cJSON_IsNumber(ps)) param_set = ps->valueint;
    }

    const char *alg = kem_alg_name(param_set);
    if (!alg) { send_error("unsupported param_set"); return; }

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) { send_error("OQS_KEM_new failed"); return; }

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);

    /* Check for deterministic randomness */
    cJSON *inputs = cJSON_GetObjectItem(req, "inputs");
    const char *rand_hex = NULL;
    if (inputs) {
        cJSON *r = cJSON_GetObjectItem(inputs, "randomness");
        if (r && cJSON_IsString(r)) rand_hex = r->valuestring;
    }

    OQS_STATUS rc;
    if (rand_hex) {
        uint8_t *seed = NULL;
        size_t seed_len = 0;
        if (hex_to_bytes(rand_hex, &seed, &seed_len) == 0 && seed_len == 64) {
            rc = OQS_KEM_keypair_derand(kem, pk, sk, seed);
        } else {
            rc = OQS_KEM_keypair(kem, pk, sk);
        }
        free(seed);
    } else {
        rc = OQS_KEM_keypair(kem, pk, sk);
    }

    if (rc != OQS_SUCCESS) {
        free(pk); free(sk); OQS_KEM_free(kem);
        send_error("keygen failed");
        return;
    }

    char *pk_hex = bytes_to_hex(pk, kem->length_public_key);
    char *sk_hex = bytes_to_hex(sk, kem->length_secret_key);

    cJSON *outputs = cJSON_CreateObject();
    cJSON_AddStringToObject(outputs, "ek", pk_hex);
    cJSON_AddStringToObject(outputs, "dk", sk_hex);
    send_outputs(outputs);

    free(pk_hex); free(sk_hex);
    free(pk); free(sk);
    OQS_KEM_free(kem);
}

/* ---------- ML_KEM_Encaps ---------- */

static void handle_kem_encaps(cJSON *req) {
    cJSON *inputs = cJSON_GetObjectItem(req, "inputs");
    if (!inputs) { send_error("missing inputs"); return; }

    cJSON *ek_json = cJSON_GetObjectItem(inputs, "ek");
    if (!ek_json || !cJSON_IsString(ek_json)) { send_error("missing ek"); return; }

    uint8_t *ek = NULL;
    size_t ek_len = 0;
    if (hex_to_bytes(ek_json->valuestring, &ek, &ek_len) != 0) {
        send_error("invalid ek hex"); return;
    }

    const char *alg = kem_alg_from_ek_len(ek_len);
    if (!alg) { free(ek); send_error("cannot determine param_set from ek length"); return; }

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) { free(ek); send_error("OQS_KEM_new failed"); return; }

    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);

    /* Check for deterministic randomness */
    const char *rand_hex = NULL;
    cJSON *r = cJSON_GetObjectItem(inputs, "randomness");
    if (r && cJSON_IsString(r)) rand_hex = r->valuestring;

    OQS_STATUS rc;
    if (rand_hex) {
        uint8_t *seed = NULL;
        size_t seed_len = 0;
        if (hex_to_bytes(rand_hex, &seed, &seed_len) == 0 && seed_len == 32) {
            rc = OQS_KEM_encaps_derand(kem, ct, ss, ek, seed);
        } else {
            rc = OQS_KEM_encaps(kem, ct, ss, ek);
        }
        free(seed);
    } else {
        rc = OQS_KEM_encaps(kem, ct, ss, ek);
    }

    if (rc != OQS_SUCCESS) {
        free(ct); free(ss); free(ek); OQS_KEM_free(kem);
        send_error("encapsulate failed");
        return;
    }

    char *ct_hex = bytes_to_hex(ct, kem->length_ciphertext);
    char *ss_hex = bytes_to_hex(ss, kem->length_shared_secret);

    cJSON *outputs = cJSON_CreateObject();
    cJSON_AddStringToObject(outputs, "c", ct_hex);
    cJSON_AddStringToObject(outputs, "K", ss_hex);
    send_outputs(outputs);

    free(ct_hex); free(ss_hex);
    free(ct); free(ss); free(ek);
    OQS_KEM_free(kem);
}

/* ---------- ML_KEM_Decaps ---------- */

static void handle_kem_decaps(cJSON *req) {
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

    const char *alg = kem_alg_from_dk_len(dk_len);
    if (!alg) { free(ct); free(dk); send_error("cannot determine param_set from dk length"); return; }

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) { free(ct); free(dk); send_error("OQS_KEM_new failed"); return; }

    uint8_t *ss = malloc(kem->length_shared_secret);
    OQS_STATUS rc = OQS_KEM_decaps(kem, ss, ct, dk);
    if (rc != OQS_SUCCESS) {
        free(ss); free(ct); free(dk); OQS_KEM_free(kem);
        send_error("decapsulate failed");
        return;
    }

    char *ss_hex = bytes_to_hex(ss, kem->length_shared_secret);

    cJSON *outputs = cJSON_CreateObject();
    cJSON_AddStringToObject(outputs, "K", ss_hex);
    send_outputs(outputs);

    free(ss_hex);
    free(ss); free(ct); free(dk);
    OQS_KEM_free(kem);
}

/* ---------- ML_DSA_KeyGen ---------- */

static void handle_sig_keygen(cJSON *req) {
    int param_set = 65;
    cJSON *params = cJSON_GetObjectItem(req, "params");
    if (params) {
        cJSON *ps = cJSON_GetObjectItem(params, "param_set");
        if (ps && cJSON_IsNumber(ps)) param_set = ps->valueint;
    }

    const char *alg = sig_alg_name(param_set);
    if (!alg) { send_error("unsupported param_set for ML-DSA"); return; }

    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) { send_error("OQS_SIG_new failed"); return; }

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);

    OQS_STATUS rc = OQS_SIG_keypair(sig, pk, sk);
    if (rc != OQS_SUCCESS) {
        free(pk); free(sk); OQS_SIG_free(sig);
        send_error("ML-DSA keygen failed");
        return;
    }

    char *pk_hex = bytes_to_hex(pk, sig->length_public_key);
    char *sk_hex = bytes_to_hex(sk, sig->length_secret_key);

    cJSON *outputs = cJSON_CreateObject();
    cJSON_AddStringToObject(outputs, "pk", pk_hex);
    cJSON_AddStringToObject(outputs, "sk", sk_hex);
    send_outputs(outputs);

    free(pk_hex); free(sk_hex);
    free(pk); free(sk);
    OQS_SIG_free(sig);
}

/* ---------- ML_DSA_Sign ---------- */

static void handle_sig_sign(cJSON *req) {
    cJSON *inputs = cJSON_GetObjectItem(req, "inputs");
    if (!inputs) { send_error("missing inputs"); return; }

    cJSON *msg_json = cJSON_GetObjectItem(inputs, "message");
    cJSON *sk_json = cJSON_GetObjectItem(inputs, "sk");
    if (!msg_json || !cJSON_IsString(msg_json)) { send_error("missing message"); return; }
    if (!sk_json || !cJSON_IsString(sk_json)) { send_error("missing sk"); return; }

    uint8_t *msg = NULL, *sk = NULL;
    size_t msg_len = 0, sk_len = 0;
    if (hex_to_bytes(msg_json->valuestring, &msg, &msg_len) != 0) { send_error("invalid message hex"); return; }
    if (hex_to_bytes(sk_json->valuestring, &sk, &sk_len) != 0) { free(msg); send_error("invalid sk hex"); return; }

    const char *alg = sig_alg_from_sk_len(sk_len);
    if (!alg) { free(msg); free(sk); send_error("cannot determine param_set from sk length"); return; }

    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) { free(msg); free(sk); send_error("OQS_SIG_new failed"); return; }

    uint8_t *signature = malloc(sig->length_signature);
    size_t sig_len = 0;

    /* Check for optional context string */
    cJSON *ctx_json = cJSON_GetObjectItem(inputs, "ctx");
    OQS_STATUS rc;
    if (ctx_json && cJSON_IsString(ctx_json)) {
        uint8_t *ctx_str = NULL;
        size_t ctx_len = 0;
        hex_to_bytes(ctx_json->valuestring, &ctx_str, &ctx_len);
        rc = OQS_SIG_sign_with_ctx_str(sig, signature, &sig_len, msg, msg_len, ctx_str, ctx_len, sk);
        free(ctx_str);
    } else {
        rc = OQS_SIG_sign(sig, signature, &sig_len, msg, msg_len, sk);
    }

    if (rc != OQS_SUCCESS) {
        free(signature); free(msg); free(sk); OQS_SIG_free(sig);
        send_error("sign failed");
        return;
    }

    char *sig_hex = bytes_to_hex(signature, sig_len);

    cJSON *outputs = cJSON_CreateObject();
    cJSON_AddStringToObject(outputs, "signature", sig_hex);
    send_outputs(outputs);

    free(sig_hex);
    free(signature); free(msg); free(sk);
    OQS_SIG_free(sig);
}

/* ---------- ML_DSA_Verify ---------- */

static void handle_sig_verify(cJSON *req) {
    cJSON *inputs = cJSON_GetObjectItem(req, "inputs");
    if (!inputs) { send_error("missing inputs"); return; }

    cJSON *msg_json = cJSON_GetObjectItem(inputs, "message");
    cJSON *sig_json = cJSON_GetObjectItem(inputs, "signature");
    cJSON *pk_json = cJSON_GetObjectItem(inputs, "pk");
    if (!msg_json || !cJSON_IsString(msg_json)) { send_error("missing message"); return; }
    if (!sig_json || !cJSON_IsString(sig_json)) { send_error("missing signature"); return; }
    if (!pk_json || !cJSON_IsString(pk_json)) { send_error("missing pk"); return; }

    uint8_t *msg = NULL, *signature = NULL, *pk = NULL;
    size_t msg_len = 0, sig_len = 0, pk_len = 0;
    if (hex_to_bytes(msg_json->valuestring, &msg, &msg_len) != 0) { send_error("invalid message hex"); return; }
    if (hex_to_bytes(sig_json->valuestring, &signature, &sig_len) != 0) { free(msg); send_error("invalid signature hex"); return; }
    if (hex_to_bytes(pk_json->valuestring, &pk, &pk_len) != 0) { free(msg); free(signature); send_error("invalid pk hex"); return; }

    const char *alg = sig_alg_from_pk_len(pk_len);
    if (!alg) { free(msg); free(signature); free(pk); send_error("cannot determine param_set from pk length"); return; }

    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) { free(msg); free(signature); free(pk); send_error("OQS_SIG_new failed"); return; }

    /* Check for optional context string */
    cJSON *ctx_json = cJSON_GetObjectItem(inputs, "ctx");
    OQS_STATUS rc;
    if (ctx_json && cJSON_IsString(ctx_json)) {
        uint8_t *ctx_str = NULL;
        size_t ctx_len = 0;
        hex_to_bytes(ctx_json->valuestring, &ctx_str, &ctx_len);
        rc = OQS_SIG_verify_with_ctx_str(sig, msg, msg_len, signature, sig_len, ctx_str, ctx_len, pk);
        free(ctx_str);
    } else {
        rc = OQS_SIG_verify(sig, msg, msg_len, signature, sig_len, pk);
    }

    cJSON *outputs = cJSON_CreateObject();
    cJSON_AddStringToObject(outputs, "valid", rc == OQS_SUCCESS ? "true" : "false");
    send_outputs(outputs);

    free(msg); free(signature); free(pk);
    OQS_SIG_free(sig);
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
        handle_kem_keygen(req);
    } else if (strcmp(fn, "ML_KEM_Encaps") == 0) {
        handle_kem_encaps(req);
    } else if (strcmp(fn, "ML_KEM_Decaps") == 0) {
        handle_kem_decaps(req);
    } else if (strcmp(fn, "ML_DSA_KeyGen") == 0) {
        handle_sig_keygen(req);
    } else if (strcmp(fn, "ML_DSA_Sign") == 0) {
        handle_sig_sign(req);
    } else if (strcmp(fn, "ML_DSA_Verify") == 0) {
        handle_sig_verify(req);
    } else {
        send_unsupported();
    }

    cJSON_Delete(req);
}

int main(void) {
    OQS_init();

    /* Send handshake */
    cJSON *handshake = cJSON_CreateObject();
    cJSON_AddStringToObject(handshake, "implementation", "liboqs");
    cJSON *funcs = cJSON_CreateStringArray(
        (const char *[]){
            "ML_KEM_KeyGen", "ML_KEM_Encaps", "ML_KEM_Decaps",
            "ML_DSA_KeyGen", "ML_DSA_Sign", "ML_DSA_Verify"
        }, 6);
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
    OQS_destroy();
    return 0;
}
