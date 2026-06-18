#ifndef crypto_common_h
#define crypto_common_h

#include <string>
#include <vector>
#include <cstdint>

enum class Algorithm {
    AFFINE,
    VERNAM
};

int generate_key_affine(const std::string& output_file);
int generate_key_vernam(const std::string& output_file, size_t key_size);

int encrypt_file(Algorithm cipher, const std::string& input_file,const std::string& output_file, const std::string& key_file);

int decrypt_file(Algorithm cipher, const std::string& input_file,const std::string& output_file, const std::string& key_file);

int encrypt_text(Algorithm cipher, const std::string& input_text,const std::string& key_file, std::vector<uint8_t>& output);

int decrypt_text(Algorithm cipher, const std::vector<uint8_t>& input,const std::string& key_file, std::string& output_text);

void print_error(int code);

#endif