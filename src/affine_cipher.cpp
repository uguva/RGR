#include "../include/affine_cipher.h"
#include <cstdlib>
#include <ctime>

static int greatest_common_divisor(int first, int second) {
    first = first < 0 ? -first : first;
    second = second < 0 ? -second : second;
    while (second != 0) {
        int remainder = first % second;
        first = second;
        second = remainder;
    }
    return first;
}

static int modular_inverse_256(int number) {
    if (number % 2 == 0) return -1;
    number = number % 256;
    for (int candidate = 1; candidate < 256; candidate++) {
        if ((number * candidate) % 256 == 1) return candidate;
    }
    return -1;
}

static int generate_random_multiplier() {
    static int seeded = 0;
    if (!seeded) {
        srand(time(NULL));
        seeded = 1;
    }
    int multiplier;
    do {
        multiplier = (rand() % 255) + 1;
    } while (greatest_common_divisor(multiplier, 256) != 1);
    return multiplier;
}

static int generate_random_shift() {
    static int seeded = 0;
    if (!seeded) {
        srand(time(NULL));
        seeded = 1;
    }
    return rand() % 256;
}

int affine_generate_key(uint8_t key[2]) {
    int multiplier = generate_random_multiplier();
    int shift = generate_random_shift();
    key[0] = (uint8_t)multiplier;
    key[1] = (uint8_t)shift;
    return 0;
}

int affine_encrypt(const uint8_t* plain_data, size_t plain_length,
                   const uint8_t* key_data, size_t key_length,
                   uint8_t* cipher_data, size_t* cipher_length) {
    if (key_length < 2) return 1;
    if (*cipher_length < plain_length) return 2;
    
    int multiplier = key_data[0];
    int shift = key_data[1];
    
    if (greatest_common_divisor(multiplier, 256) != 1) return 3;
    
    for (size_t i = 0; i < plain_length; i++) {
        cipher_data[i] = (multiplier * plain_data[i] + shift) % 256;
    }
    *cipher_length = plain_length;
    return 0;
}

int affine_decrypt(const uint8_t* cipher_data, size_t cipher_length,
                   const uint8_t* key_data, size_t key_length,
                   uint8_t* plain_data, size_t* plain_length) {
    if (key_length < 2) return 1;
    if (*plain_length < cipher_length) return 2;
    
    int multiplier = key_data[0];
    int shift = key_data[1];
    
    int inverse_multiplier = modular_inverse_256(multiplier);
    if (inverse_multiplier == -1) return 3;
    
    for (size_t i = 0; i < cipher_length; i++) {
        int encrypted_byte = cipher_data[i];
        int decrypted_byte = (inverse_multiplier * ((encrypted_byte - shift + 256) % 256)) % 256;
        plain_data[i] = (uint8_t)decrypted_byte;
    }
    *plain_length = cipher_length;
    return 0;
}