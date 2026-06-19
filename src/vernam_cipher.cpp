#include "../include/vernam_cipher.h"
#include <cstdlib>
#include <ctime>

extern "C" int vernam_generate_key(uint8_t* key_buffer, size_t key_size) {
    static int seeded = 0;
    if (!seeded) {
        srand(time(NULL));
        seeded = 1;
    }
    for (size_t i = 0; i < key_size; i++) {
        key_buffer[i] = (uint8_t)(rand() % 256);
    }
    return 0;
}

extern "C" int vernam_process(const uint8_t* input_data, size_t input_length,const uint8_t* key_data, size_t key_length,uint8_t* output_data, size_t* output_length) {
    if (key_length < input_length) return 1;
    if (*output_length < input_length) return 2;
    
    for (size_t i = 0; i < input_length; i++) {
        output_data[i] = input_data[i] ^ key_data[i];
    }
    *output_length = input_length;
    return 0;
}

extern "C" int vernam_encrypt(const uint8_t* plain_data, size_t plain_length,const uint8_t* key_data, size_t key_length,uint8_t* cipher_data, size_t* cipher_length) {
    return vernam_process(plain_data, plain_length, key_data, key_length, cipher_data, cipher_length);
}

extern "C" int vernam_decrypt(const uint8_t* cipher_data, size_t cipher_length,const uint8_t* key_data, size_t key_length,uint8_t* plain_data, size_t* plain_length) {
    return vernam_process(cipher_data, cipher_length, key_data, key_length, plain_data, plain_length);
}