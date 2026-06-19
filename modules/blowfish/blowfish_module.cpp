#include "crypto_interface.h"
#include <openssl/blowfish.h>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <ctime>

using namespace std;

extern "C" {
    const AlgorithmInfo* get_algorithm_info() {
        static const AlgorithmInfo info = { "Blowfish", 0 };
        return &info;
    }

    CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
        if (!out_size) return CryptoStatus::InvalidParam;
        if (is_encrypt) {
            size_t padding = 8 - (input_size % 8);
            *out_size = input_size + (padding == 0 ? 8 : padding);
        } else {
            *out_size = input_size; 
        }
        return CryptoStatus::Success;
    }

    CryptoStatus generate_keys(const char* params, char* out_buffer, size_t max_size, size_t* written) {
        if (max_size < 56) return CryptoStatus::BufferTooSmall;
        srand(static_cast<unsigned>(time(nullptr)));
        string key = "";
        for(int i = 0; i < 32; i++) { // 32 байта ключа
            key += static_cast<char>((rand() % 94) + 33);
        }
        strcpy(out_buffer, key.c_str());
        *written = key.length();
        return CryptoStatus::Success;
    }

    CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        if (!input.data || !key.data || !output.data) return CryptoStatus::InvalidParam;
        if (key.size == 0 || key.size > 56) return CryptoStatus::InvalidParam;

        uint8_t padding_size = static_cast<uint8_t>(8 - (input.size % 8));
        if (padding_size == 0) padding_size = 8;
        size_t padded_length = input.size + padding_size;
        
        if (output.size < padded_length) return CryptoStatus::BufferTooSmall;

        vector<uint8_t> padded_data(input.data, input.data + input.size);
        for (uint8_t i = 0; i < padding_size; ++i) {
            padded_data.push_back(padding_size);
        }

        BF_KEY blowfish_key;
        BF_set_key(&blowfish_key, static_cast<int>(key.size), key.data);

        for (size_t offset = 0; offset < padded_length; offset += 8) {
            BF_ecb_encrypt(&padded_data[offset], &output.data[offset], &blowfish_key, BF_ENCRYPT);
        }
        
        secure_memory_clear(padded_data);
        return CryptoStatus::Success;
    }

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        if (!input.data || !key.data || !output.data) return CryptoStatus::InvalidParam;
        if (key.size == 0 || key.size > 56) return CryptoStatus::InvalidParam;
        if (input.size % 8 != 0) return CryptoStatus::InvalidParam;
        if (output.size < input.size) return CryptoStatus::BufferTooSmall;

        BF_KEY blowfish_key;
        BF_set_key(&blowfish_key, static_cast<int>(key.size), key.data);

        vector<uint8_t> decrypted_data(input.size);
        for (size_t offset = 0; offset < input.size; offset += 8) {
            BF_ecb_encrypt(&input.data[offset], &decrypted_data[offset], &blowfish_key, BF_DECRYPT);
        }

        uint8_t padding_size = decrypted_data.back();
        if (padding_size == 0 || padding_size > 8 || padding_size > decrypted_data.size()) {
            secure_memory_clear(decrypted_data);
            return CryptoStatus::UnknownError; // Ошибка паддинга (неверный ключ)
        }

        size_t actual_size = decrypted_data.size() - padding_size;
        memcpy(output.data, decrypted_data.data(), actual_size);
        
        // Зануляем остаток буфера, чтобы скрыть паддинг
        for (size_t i = actual_size; i < output.size; ++i) output.data[i] = 0;

        secure_memory_clear(decrypted_data);
        return CryptoStatus::Success;
    }
}