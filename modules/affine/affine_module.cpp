#include "crypto_interface.h"
#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <cstring>

using namespace std;

namespace {
    // Вспомогательные математические функции из кода одногруппника
    int greatest_common_divisor(int first, int second) {
        first = first < 0 ? -first : first;
        second = second < 0 ? -second : second;
        while (second != 0) {
            int remainder = first % second;
            first = second;
            second = remainder;
        }
        return first;
    }

    int modular_inverse_256(int number) {
        if (number % 2 == 0) return -1;
        number = number % 256;
        for (int candidate = 1; candidate < 256; candidate++) {
            if ((number * candidate) % 256 == 1) return candidate;
        }
        return -1;
    }
}

extern "C" {
    const AlgorithmInfo* get_algorithm_info() {
        static const AlgorithmInfo info = { "Affine", 2 };
        return &info;
    }

    CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
        if (!out_size) return CryptoStatus::InvalidParam;
        *out_size = input_size; // Размер не меняется
        return CryptoStatus::Success;
    }

    CryptoStatus generate_keys(const char* params, char* out_buffer, size_t max_size, size_t* written) {
        srand(static_cast<unsigned>(time(nullptr)));
        
        // Multiplier (A) должен быть взаимно прост с 256 (т.е. быть нечетным числом)
        int a;
        do {
            a = (rand() % 255) + 1;
        } while (greatest_common_divisor(a, 256) != 1);
        
        // Shift (B) - любое число от 0 до 255
        int b = rand() % 256;

        string res = to_string(a) + " " + to_string(b);
        
        if (res.size() >= max_size) return CryptoStatus::BufferTooSmall;
        strcpy(out_buffer, res.c_str());
        *written = res.size();
        return CryptoStatus::Success;
    }

    CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        string k(reinterpret_cast<const char*>(key.data), key.size);
        int a = 0, b = 0;
        
        if (sscanf(k.c_str(), "%d %d", &a, &b) != 2) return CryptoStatus::InvalidParam;
        if (greatest_common_divisor(a, 256) != 1) return CryptoStatus::InvalidParam;
        if (output.size < input.size) return CryptoStatus::BufferTooSmall;

        for (size_t i = 0; i < input.size; i++) {
            output.data[i] = static_cast<uint8_t>((a * input.data[i] + b) % 256);
        }
        return CryptoStatus::Success;
    }

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        string k(reinterpret_cast<const char*>(key.data), key.size);
        int a = 0, b = 0;
        
        if (sscanf(k.c_str(), "%d %d", &a, &b) != 2) return CryptoStatus::InvalidParam;
        
        int a_inv = modular_inverse_256(a);
        if (a_inv == -1) return CryptoStatus::InvalidParam;
        if (output.size < input.size) return CryptoStatus::BufferTooSmall;

        for (size_t i = 0; i < input.size; i++) {
            int encrypted_byte = input.data[i];
            int decrypted_byte = (a_inv * ((encrypted_byte - b + 256) % 256)) % 256;
            output.data[i] = static_cast<uint8_t>(decrypted_byte);
        }
        return CryptoStatus::Success;
    }
}
