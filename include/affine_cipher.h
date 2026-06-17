#ifndef affine_cipher_h
#define affine_cipher_h

#include <cstdint>
#include <vector>
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

int affine_generate_key(uint8_t key[2]);

int affine_encrypt(const uint8_t* plain_data, size_t plain_length,const uint8_t* key_data, size_t key_length,uint8_t* cipher_data, size_t* cipher_length);

int affine_decrypt(const uint8_t* cipher_data, size_t cipher_length,const uint8_t* key_data, size_t key_length,uint8_t* plain_data, size_t* plain_length);

#ifdef __cplusplus
}
#endif

#endif