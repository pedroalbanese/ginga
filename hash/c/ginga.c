#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define GINGA_BLOCK_SIZE 32
#define GINGA_DIGEST_SIZE 32
#define GINGA_ROUNDS 8

uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

uint32_t confuse32(uint32_t x) {
    x ^= 0xA5A5A5A5;
    x = (x + 0x3C3C3C3C);
    x = rotl32(x, 7);
    return x;
}

uint32_t round32(uint32_t x, uint32_t k, int r) {
    x = (x + k);
    x = confuse32(x);
    x = rotl32(x, (r + 3) & 31);
    x ^= k;
    x = rotl32(x, (r + 5) & 31);
    return x;
}

uint32_t subKey32(uint32_t *k, int round, int i) {
    uint32_t base = k[(i + round) & 7];
    return rotl32(base ^ (i * 73 + round * 91), (round + i) & 31);
}

void mixState512(uint32_t *state) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= rotl32(state[(i + 3) & 15], (7 * i + 13) & 31);
    }
}

void ginga_hash(const uint8_t *msg, size_t len, uint8_t out[GINGA_DIGEST_SIZE]) {
    uint32_t state[16] = {
        0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
        0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
        0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
        0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
    };

    size_t total_len = len + 1 + 8;
    size_t pad_len = (GINGA_BLOCK_SIZE - (total_len % GINGA_BLOCK_SIZE)) % GINGA_BLOCK_SIZE;
    total_len += pad_len;

    uint8_t *buffer = calloc(1, total_len);
    memcpy(buffer, msg, len);
    buffer[len] = 0x80;
    uint64_t bitlen = (uint64_t)len * 8;
    memcpy(buffer + total_len - 8, &bitlen, 8);

    for (size_t i = 0; i < total_len; i += GINGA_BLOCK_SIZE) {
        uint32_t m[8];
        for (int j = 0; j < 8; j++) {
            m[j] = ((uint32_t)buffer[i + j * 4 + 0]) |
                   ((uint32_t)buffer[i + j * 4 + 1] << 8) |
                   ((uint32_t)buffer[i + j * 4 + 2] << 16) |
                   ((uint32_t)buffer[i + j * 4 + 3] << 24);
        }

        uint32_t prev[16];
        memcpy(prev, state, sizeof(state));

        for (int r = 0; r < GINGA_ROUNDS; r++) {
            for (int j = 0; j < 16; j++) {
                uint32_t k = subKey32(m, r, j & 7);
                state[j] = round32(state[j], k, r);
            }
            mixState512(state);
        }

        for (int j = 0; j < 16; j++) {
            state[j] ^= m[j & 7] ^ prev[j];
        }
    }

    for (int i = 0; i < 8; i++) {
        out[i * 4 + 0] = state[i] & 0xFF;
        out[i * 4 + 1] = (state[i] >> 8) & 0xFF;
        out[i * 4 + 2] = (state[i] >> 16) & 0xFF;
        out[i * 4 + 3] = (state[i] >> 24) & 0xFF;
    }

    free(buffer);
}

void hmac_ginga(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[GINGA_DIGEST_SIZE]) {
    uint8_t k[GINGA_BLOCK_SIZE];
    memset(k, 0, GINGA_BLOCK_SIZE);

    if (key_len > GINGA_BLOCK_SIZE) {
        ginga_hash(key, key_len, k);
    } else {
        memcpy(k, key, key_len);
    }

    uint8_t o_key_pad[GINGA_BLOCK_SIZE], i_key_pad[GINGA_BLOCK_SIZE];
    for (int i = 0; i < GINGA_BLOCK_SIZE; i++) {
        o_key_pad[i] = k[i] ^ 0x5c;
        i_key_pad[i] = k[i] ^ 0x36;
    }

    uint8_t inner_input[GINGA_BLOCK_SIZE + msg_len];
    memcpy(inner_input, i_key_pad, GINGA_BLOCK_SIZE);
    memcpy(inner_input + GINGA_BLOCK_SIZE, msg, msg_len);

    uint8_t inner_hash[GINGA_DIGEST_SIZE];
    ginga_hash(inner_input, sizeof(inner_input), inner_hash);

    uint8_t outer_input[GINGA_BLOCK_SIZE + GINGA_DIGEST_SIZE];
    memcpy(outer_input, o_key_pad, GINGA_BLOCK_SIZE);
    memcpy(outer_input + GINGA_BLOCK_SIZE, inner_hash, GINGA_DIGEST_SIZE);

    ginga_hash(outer_input, sizeof(outer_input), out);
}

void hkdf_ginga(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,
                const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len) {
    uint8_t prk[GINGA_DIGEST_SIZE];

    uint8_t null_salt[GINGA_DIGEST_SIZE] = {0};
    if (salt == NULL) {
        salt = null_salt;
        salt_len = GINGA_DIGEST_SIZE;
    }

    hmac_ginga(salt, salt_len, ikm, ikm_len, prk);

    uint8_t t[GINGA_DIGEST_SIZE];
    size_t pos = 0;
    uint8_t counter = 1;
    size_t len = 0;

    while (pos < okm_len) {
        uint8_t input[GINGA_DIGEST_SIZE + info_len + 1];
        len = 0;
        if (counter > 1) {
            memcpy(input, t, GINGA_DIGEST_SIZE);
            len += GINGA_DIGEST_SIZE;
        }
        memcpy(input + len, info, info_len);
        len += info_len;
        input[len++] = counter;

        hmac_ginga(prk, GINGA_DIGEST_SIZE, input, len, t);
        size_t copy_len = (okm_len - pos < GINGA_DIGEST_SIZE) ? (okm_len - pos) : GINGA_DIGEST_SIZE;
        memcpy(okm + pos, t, copy_len);
        pos += copy_len;
        counter++;
    }
}

// --- Exemplo de uso ---
int main() {
    const char *mensagem = "Exemplo da função hash Ginga em C.";
    const char *chave = "chave-secreta";

    uint8_t hash[GINGA_DIGEST_SIZE];
    ginga_hash((const uint8_t *)mensagem, strlen(mensagem), hash);

    printf("Hash (hex): ");
    for (int i = 0; i < GINGA_DIGEST_SIZE; i++) printf("%02x", hash[i]);
    printf("\n");

    uint8_t hmac[GINGA_DIGEST_SIZE];
    hmac_ginga((const uint8_t *)chave, strlen(chave), (const uint8_t *)mensagem, strlen(mensagem), hmac);

    printf("HMAC-Ginga (hex): ");
    for (int i = 0; i < GINGA_DIGEST_SIZE; i++) printf("%02x", hmac[i]);
    printf("\n");

    const char *key_material = "material-chave-bruto";
    const char *salt = "sal-de-exemplo";
    const char *info = "contexto";

    uint8_t okm[64];
    hkdf_ginga((const uint8_t *)key_material, strlen(key_material),
               (const uint8_t *)salt, strlen(salt),
               (const uint8_t *)info, strlen(info),
               okm, sizeof(okm));

    printf("HKDF-Ginga OKM (hex): ");
    for (int i = 0; i < sizeof(okm); i++) printf("%02x", okm[i]);
    printf("\n");

    return 0;
}
