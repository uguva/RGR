#include "crypto_interface.h"
#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <cstring>

using namespace std;

extern "C" {
    const AlgorithmInfo* get_algorithm_info() {
        static const AlgorithmInfo info = { "Vernam", 0 }; // Длина ключа переменная
        return &info;
    }

    CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
        if (!out_size) return CryptoStatus::InvalidParam;
        *out_size = input_size;
        return CryptoStatus::Success;
    }

    CryptoStatus generate_keys(const char* params, char* out_buffer, size_t max_size, size_t* written) {
        if (!params || strlen(params) == 0) {
            return CryptoStatus::InvalidParam;
        }

        for (size_t i = 0; params[i] != '\0'; ++i) {
            // Пропускаем пробелы в начале или конце
            if (isspace(static_cast<unsigned char>(params[i]))) {
                continue;
            }
            if (!isdigit(static_cast<unsigned char>(params[i]))) {
                return CryptoStatus::InvalidParam; // Найдена буква или спецсимвол -> ошибка!
            }
        }

        int length = 0;
        if (sscanf(params, "%d", &length) != 1 || length <= 0) {
            return CryptoStatus::InvalidParam;
        }

        if (static_cast<size_t>(length) >= max_size) {
            return CryptoStatus::BufferTooSmall;
        }

        srand(static_cast<unsigned>(time(nullptr)));
        string res = "";
        for (int i = 0; i < length; i++) {
            // Читаемые ASCII символы
            res += static_cast<char>((rand() % 94) + 33);
        }

        strcpy(out_buffer, res.c_str());
        *written = res.size();
        return CryptoStatus::Success;
    }

    CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        if (key.size < input.size) return CryptoStatus::InvalidParam;
        if (output.size < input.size) return CryptoStatus::BufferTooSmall;

        for (size_t i = 0; i < input.size; i++) {
            output.data[i] = input.data[i] ^ key.data[i];
        }
        return CryptoStatus::Success;
    }

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        // Дешифрование (XOR)
        return encrypt(input, key, output);
    }
}
