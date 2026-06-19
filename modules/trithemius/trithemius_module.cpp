#include "crypto_interface.h"
#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <cstring>

using namespace std;

static uint8_t get_initial_shift(const char* key_text, size_t key_len) {
    if (key_len == 0) return 0;
    int shift_value = 0;
    for (size_t i = 0; i < key_len; ++i) {
        if (key_text[i] < '0' || key_text[i] > '9') return 0;
        shift_value = shift_value * 10 + (key_text[i] - '0');
    }
    return static_cast<uint8_t>(shift_value % 256);
}

extern "C" {
    const AlgorithmInfo* get_algorithm_info() {
        static const AlgorithmInfo info = { "Trithemius", 0 };
        return &info;
    }

    CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
        if (!out_size) return CryptoStatus::InvalidParam;
        *out_size = input_size;
        return CryptoStatus::Success;
    }

    CryptoStatus generate_keys(const char* params, char* out_buffer, size_t max_size, size_t* written) {
        if (max_size < 10) return CryptoStatus::BufferTooSmall;
        srand(static_cast<unsigned>(time(nullptr)));
        string key = to_string(rand() % 256);
        strncpy(out_buffer, key.c_str(), max_size);
        *written = key.length();
        return CryptoStatus::Success;
    }

    CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        uint8_t initial_shift = get_initial_shift(reinterpret_cast<const char*>(key.data), key.size);
        for (size_t i = 0; i < input.size; ++i) {
            output.data[i] = static_cast<uint8_t>((input.data[i] + initial_shift + i) % 256);
        }
        return CryptoStatus::Success;
    }

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        uint8_t initial_shift = get_initial_shift(reinterpret_cast<const char*>(key.data), key.size);
        for (size_t i = 0; i < input.size; ++i) {
            uint16_t val = (input.data[i] + 256 - ((initial_shift + i) % 256)) % 256;
            output.data[i] = static_cast<uint8_t>(val);
        }
        return CryptoStatus::Success;
    }
}