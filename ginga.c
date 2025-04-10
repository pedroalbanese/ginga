#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BLOCK_SIZE 16
#define ROUNDS 16

// --- ARX operations (iguais) ---

uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

uint32_t confuse32(uint32_t x) {
    x ^= 0xA5A5A5A5;
    x += 0x3C3C3C3C;
    return rotl32(x, 7);
}

uint32_t deconfuse32(uint32_t x) {
    x = rotr32(x, 7);
    x -= 0x3C3C3C3C;
    x ^= 0xA5A5A5A5;
    return x;
}

uint32_t round32(uint32_t x, uint32_t k, int r) {
    x += k;
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

void mixState32(uint32_t *state) {
    state[0] ^= rotl32(state[1], 5);
    state[1] ^= rotl32(state[2], 11);
    state[2] ^= rotl32(state[3], 17);
    state[3] ^= rotl32(state[0], 23);
}

// --- Cifra Ginga com bloco de 16 bytes ---

void ginga_block_encrypt(const uint8_t *input, const uint8_t *key, uint8_t *output) {
    uint32_t c[4], k[8];
    memcpy(c, input, 16);
    memcpy(k, key, 32);

    for (int r = 0; r < ROUNDS; r++) {
        for (int i = 0; i < 4; i++) {
            uint32_t subk = subKey32(k, r, i);
            c[i] = round32(c[i], subk, r);
        }
        mixState32(c);
    }
    memcpy(output, c, 16);
}

// --- CTR Mode ---

void increment_counter(uint8_t *counter) {
    for (int i = BLOCK_SIZE - 1; i >= 0; i--) {
        if (++counter[i]) break;
    }
}

void ginga_ctr_crypt(const uint8_t *input, const uint8_t *key, uint8_t *output, size_t len, uint8_t *iv) {
    uint8_t keystream[BLOCK_SIZE];
    uint8_t counter[BLOCK_SIZE];
    memcpy(counter, iv, BLOCK_SIZE);

    for (size_t i = 0; i < len; i += BLOCK_SIZE) {
        ginga_block_encrypt(counter, key, keystream);
        size_t block_len = (len - i < BLOCK_SIZE) ? len - i : BLOCK_SIZE;

        for (size_t j = 0; j < block_len; j++)
            output[i + j] = input[i + j] ^ keystream[j];

        increment_counter(counter);
    }
}

// --- Exemplo principal ---

int main() {
    uint8_t key[32] = {0};
    uint8_t iv[BLOCK_SIZE] = {0};

    const char *text = "Mensagem secreta em modo CTR sem padding";
    size_t len = strlen(text);

    uint8_t ciphertext[128] = {0};
    uint8_t decrypted[128] = {0};

    ginga_ctr_crypt((uint8_t *)text, key, ciphertext, len, iv);

    // Reset IV para descriptografar
    memset(iv, 0, BLOCK_SIZE);
    ginga_ctr_crypt(ciphertext, key, decrypted, len, iv);

    printf("Texto original:      %s\n", text);
    printf("Ciphertext (hex):    ");
    for (size_t i = 0; i < len; i++) printf("%02x", ciphertext[i]);
    printf("\nTexto descriptografado: %s\n", decrypted);

    return 0;
}
