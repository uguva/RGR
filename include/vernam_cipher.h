#ifndef vernam_cipher_h
#define vernam_cipher_h

#include <cstdint>
#include <vector>
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

int vernam_generate_key(uint8_t* key_buffer, size_t key_size);

int vernam_process(const uint8_t* input_data, size_t input_length,const uint8_t* key_data, size_t key_length,uint8_t* output_data, size_t* output_length);

int vernam_encrypt(const uint8_t* plain_data, size_t plain_length,const uint8_t* key_data, size_t key_length,uint8_t* cipher_data, size_t* cipher_length);

int vernam_decrypt(const uint8_t* cipher_data, size_t cipher_length,const uint8_t* key_data, size_t key_length,uint8_t* plain_data, size_t* plain_length);

#ifdef __cplusplus
}
#endif

#endif