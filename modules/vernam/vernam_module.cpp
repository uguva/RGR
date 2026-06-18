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
        // Ожидаем, что в параметрах передадут желаемую длину ключа
        int length = 0;
        if (sscanf(params, "%d", &length) != 1 || length <= 0) {
            return CryptoStatus::InvalidParam;
        }

        if (static_cast<size_t>(length) >= max_size) return CryptoStatus::BufferTooSmall;

        srand(static_cast<unsigned>(time(nullptr)));
        string res = "";
        for (int i = 0; i < length; i++) {
            // Генерируем читаемые ASCII символы (от 33 '!' до 126 '~') 
            // Это безопасно для консольного вывода и сохранения в текстовые файлы
            res += static_cast<char>((rand() % 94) + 33);
        }

        strcpy(out_buffer, res.c_str());
        *written = res.size();
        return CryptoStatus::Success;
    }

    CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        // Академическое правило шифра Вернама: ключ должен быть >= длины сообщения
        if (key.size < input.size) return CryptoStatus::InvalidParam;
        if (output.size < input.size) return CryptoStatus::BufferTooSmall;

        for (size_t i = 0; i < input.size; i++) {
            output.data[i] = input.data[i] ^ key.data[i];
        }
        return CryptoStatus::Success;
    }

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        // Дешифрование в Вернаме абсолютно идентично шифрованию (XOR)
        return encrypt(input, key, output);
    }
}
