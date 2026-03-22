/*
 * Crucible ML-KEM Harness for itzmeanjan/ml-kem (C++20 header-only)
 *
 * This wraps the header-only C++20 ML-KEM implementation.
 * keygen(d, z, pubkey, seckey) -- d=32 bytes, z=32 bytes
 * encapsulate(m, pubkey, cipher, shared_secret) -- m=32 bytes
 * decapsulate(seckey, cipher, shared_secret)
 *
 * The "randomness" input for KeyGen is 64 bytes = d || z
 * The "randomness" input for Encaps is 32 bytes = m
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <array>
#include <span>
#include <string>

extern "C" {
#include "cJSON.h"
}

#include "ml_kem/ml_kem_768.hpp"

#define MAX_LINE (1024 * 1024)
static char line_buf[MAX_LINE];

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
    if (!item || !cJSON_IsString(item)) return nullptr;
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

static void send_unsupported() {
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "unsupported", 1);
    send_json(resp);
}

static void handle_keygen(cJSON *inputs, cJSON *params) {
    int param_set = get_param_int(params, "param_set", 768);

    if (param_set != 768) {
        send_error("only param_set=768 supported in this build");
        return;
    }

    const char *rand_hex = get_input_str(inputs, "randomness");

    std::array<uint8_t, ml_kem_768::SEED_D_BYTE_LEN> d{};
    std::array<uint8_t, ml_kem_768::SEED_Z_BYTE_LEN> z{};
    std::array<uint8_t, ml_kem_768::PKEY_BYTE_LEN> pubkey{};
    std::array<uint8_t, ml_kem_768::SKEY_BYTE_LEN> seckey{};

    if (rand_hex) {
        uint8_t coins[64];
        size_t coins_len;
        if (hex_decode(rand_hex, coins, sizeof(coins), &coins_len) != 0 || coins_len != 64) {
            send_error("randomness must be 64 bytes hex");
            return;
        }
        /* randomness = d (32 bytes) || z (32 bytes) */
        memcpy(d.data(), coins, 32);
        memcpy(z.data(), coins + 32, 32);
    } else {
        /* Generate random d and z using /dev/urandom */
        FILE *f = fopen("/dev/urandom", "rb");
        if (!f) { send_error("cannot open /dev/urandom"); return; }
        if (fread(d.data(), 1, 32, f) != 32 || fread(z.data(), 1, 32, f) != 32) {
            fclose(f);
            send_error("failed to read random bytes");
            return;
        }
        fclose(f);
    }

    ml_kem_768::keygen(d, z, pubkey, seckey);

    constexpr size_t pk_bytes = ml_kem_768::PKEY_BYTE_LEN;
    constexpr size_t sk_bytes = ml_kem_768::SKEY_BYTE_LEN;
    char pk_hex[pk_bytes * 2 + 1];
    char sk_hex[sk_bytes * 2 + 1];
    hex_encode(pubkey.data(), pk_bytes, pk_hex);
    hex_encode(seckey.data(), sk_bytes, sk_hex);

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

    std::array<uint8_t, ml_kem_768::PKEY_BYTE_LEN> pubkey{};
    size_t pk_len;
    if (hex_decode(ek_hex, pubkey.data(), pubkey.size(), &pk_len) != 0 ||
        pk_len != ml_kem_768::PKEY_BYTE_LEN) {
        send_error("invalid ek length");
        return;
    }

    std::array<uint8_t, ml_kem_768::SEED_M_BYTE_LEN> m{};
    const char *rand_hex = get_input_str(inputs, "randomness");
    if (rand_hex) {
        size_t m_len;
        if (hex_decode(rand_hex, m.data(), m.size(), &m_len) != 0 || m_len != 32) {
            send_error("randomness must be 32 bytes hex");
            return;
        }
    } else {
        FILE *f = fopen("/dev/urandom", "rb");
        if (!f) { send_error("cannot open /dev/urandom"); return; }
        if (fread(m.data(), 1, 32, f) != 32) {
            fclose(f);
            send_error("failed to read random bytes");
            return;
        }
        fclose(f);
    }

    std::array<uint8_t, ml_kem_768::CIPHER_TEXT_BYTE_LEN> cipher{};
    std::array<uint8_t, ml_kem_768::SHARED_SECRET_BYTE_LEN> shared_secret{};

    bool ok = ml_kem_768::encapsulate(m, pubkey, cipher, shared_secret);
    if (!ok) {
        send_error("encapsulation failed (invalid public key)");
        return;
    }

    constexpr size_t ct_bytes = ml_kem_768::CIPHER_TEXT_BYTE_LEN;
    constexpr size_t ss_bytes = ml_kem_768::SHARED_SECRET_BYTE_LEN;
    char ct_hex[ct_bytes * 2 + 1];
    char ss_hex[ss_bytes * 2 + 1];
    hex_encode(cipher.data(), ct_bytes, ct_hex);
    hex_encode(shared_secret.data(), ss_bytes, ss_hex);

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

    std::array<uint8_t, ml_kem_768::CIPHER_TEXT_BYTE_LEN> cipher{};
    std::array<uint8_t, ml_kem_768::SKEY_BYTE_LEN> seckey{};
    size_t ct_len, sk_len;

    if (hex_decode(c_hex, cipher.data(), cipher.size(), &ct_len) != 0 ||
        ct_len != ml_kem_768::CIPHER_TEXT_BYTE_LEN) {
        send_error("invalid ciphertext length");
        return;
    }
    if (hex_decode(dk_hex, seckey.data(), seckey.size(), &sk_len) != 0 ||
        sk_len != ml_kem_768::SKEY_BYTE_LEN) {
        send_error("invalid dk length");
        return;
    }

    std::array<uint8_t, ml_kem_768::SHARED_SECRET_BYTE_LEN> shared_secret{};
    ml_kem_768::decapsulate(seckey, cipher, shared_secret);

    constexpr size_t ss_bytes = ml_kem_768::SHARED_SECRET_BYTE_LEN;
    char ss_hex[ss_bytes * 2 + 1];
    hex_encode(shared_secret.data(), ss_bytes, ss_hex);

    cJSON *resp = cJSON_CreateObject();
    cJSON *outputs = cJSON_CreateObject();
    cJSON_AddStringToObject(outputs, "K", ss_hex);
    cJSON_AddItemToObject(resp, "outputs", outputs);
    send_json(resp);
}

int main() {
    /* Handshake */
    cJSON *hs = cJSON_CreateObject();
    cJSON_AddStringToObject(hs, "implementation", "itzmeanjan-mlkem-cpp20");
    cJSON *funcs = cJSON_CreateArray();
    cJSON_AddItemToArray(funcs, cJSON_CreateString("ML_KEM_KeyGen"));
    cJSON_AddItemToArray(funcs, cJSON_CreateString("ML_KEM_Encaps"));
    cJSON_AddItemToArray(funcs, cJSON_CreateString("ML_KEM_Decaps"));
    cJSON_AddItemToObject(hs, "functions", funcs);
    send_json(hs);

    /* Main loop */
    while (fgets(line_buf, sizeof(line_buf), stdin) != nullptr) {
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
        cJSON *params_obj = cJSON_GetObjectItemCaseSensitive(req, "params");

        if (!func || !cJSON_IsString(func)) {
            send_error("missing 'function' field");
            cJSON_Delete(req);
            continue;
        }

        const char *fn = func->valuestring;
        if (strcmp(fn, "ML_KEM_KeyGen") == 0) {
            handle_keygen(inputs, params_obj);
        } else if (strcmp(fn, "ML_KEM_Encaps") == 0) {
            handle_encaps(inputs, params_obj);
        } else if (strcmp(fn, "ML_KEM_Decaps") == 0) {
            handle_decaps(inputs, params_obj);
        } else {
            send_unsupported();
        }

        cJSON_Delete(req);
    }

    return 0;
}
