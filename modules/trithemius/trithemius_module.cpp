#include "crypto_interface.h"
#include "blowfish_trithemius.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <gmp.h>
#include <string>
#include <vector>

using namespace std;

class TrithemiusCipherModule : public IEncryptionModule {
private:
    uint8_t get_initial_shift(const string& key_text) const {
        if (key_text.empty()) {
            return 0;
        }

        mpz_t key_value;
        mpz_init(key_value);

        // Преобразуем очень большой числовой ключ из строки в mpz_t
        if (mpz_set_str(key_value, key_text.c_str(), 10) != 0) {
            mpz_clear(key_value);
            return 0;
        }

        // Берём остаток ключа по модулю 256
        uint8_t shift = static_cast<uint8_t>(mpz_fdiv_ui(key_value, 256));

        mpz_clear(key_value);
        return shift;
    }

public:
    vector<uint8_t> encrypt(const vector<uint8_t>& input_data,
                            const string& key_text) override {
        vector<uint8_t> encrypted_data;
        encrypted_data.reserve(input_data.size());

        uint8_t initial_shift = get_initial_shift(key_text);

        for (size_t byte_index = 0; byte_index < input_data.size(); ++byte_index) {
            mpz_t current_shift;
            mpz_init_set_ui(current_shift, initial_shift);

            // current_shift = initial_shift + номер байта
            mpz_add_ui(current_shift, current_shift, byte_index);

            // Берём сдвиг по модулю 256
            uint8_t shift_mod =
                static_cast<uint8_t>(mpz_fdiv_ui(current_shift, 256));

            uint8_t encrypted_byte =
                static_cast<uint8_t>((input_data[byte_index] + shift_mod) % 256);

            encrypted_data.push_back(encrypted_byte);

            mpz_clear(current_shift);
        }

        return encrypted_data;
    }

    vector<uint8_t> decrypt(const vector<uint8_t>& encrypted_data,
                            const string& key_text) override {
        vector<uint8_t> decrypted_data;
        decrypted_data.reserve(encrypted_data.size());

        uint8_t initial_shift = get_initial_shift(key_text);

        for (size_t byte_index = 0; byte_index < encrypted_data.size(); ++byte_index) {
            mpz_t current_shift;
            mpz_init_set_ui(current_shift, initial_shift);

            // Получаем такой же сдвиг, что был при шифровании
            mpz_add_ui(current_shift, current_shift, byte_index);

            uint8_t shift_mod =
                static_cast<uint8_t>(mpz_fdiv_ui(current_shift, 256));

            uint8_t decrypted_byte =
                static_cast<uint8_t>(
                    (encrypted_data[byte_index] + 256 - shift_mod) % 256
                );

            decrypted_data.push_back(decrypted_byte);

            mpz_clear(current_shift);
        }

        return decrypted_data;
    }

    string get_name() const override {
        return "Trithemius";
    }

    string get_extension() const override {
        return ".enc";
    }
};

static TrithemiusCipherModule g_instance;

extern "C" {
    const AlgorithmInfo* get_algorithm_info() {
        static const AlgorithmInfo info = { "Trithemius", 0 };
        return &info;
    }

    CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
        *out_size = input_size;
        return CryptoStatus::Success;
    }

    CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        vector<uint8_t> input_vector(input.data, input.data + input.size);

        string key_string(
            reinterpret_cast<const char*>(key.data),
            key.size
        );

        vector<uint8_t> result = g_instance.encrypt(input_vector, key_string);

        if (output.size < result.size()) {
            return CryptoStatus::BufferTooSmall;
        }

        copy(result.begin(), result.end(), output.data);

        return CryptoStatus::Success;
    }

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        vector<uint8_t> input_vector(input.data, input.data + input.size);

        string key_string(
            reinterpret_cast<const char*>(key.data),
            key.size
        );

        vector<uint8_t> result = g_instance.decrypt(input_vector, key_string);

        if (output.size < result.size()) {
            return CryptoStatus::BufferTooSmall;
        }

        copy(result.begin(), result.end(), output.data);

        return CryptoStatus::Success;
    }

    CryptoStatus generate_keys(
        const char* params,
        char* out_buffer,
        size_t max_size,
        size_t* written
    ) {
        if (!params || max_size < 2) {
            return CryptoStatus::BufferTooSmall;
        }

        // Большое число GMP будет использоваться как начальное значение
        mpz_t seed;
        mpz_init_set_ui(seed, 0);

        for (size_t index = 0; params[index] != '\0'; ++index) {
            mpz_mul_ui(seed, seed, 131);
            mpz_add_ui(seed, seed, static_cast<unsigned char>(params[index]));
        }

        // Инициализируем генератор случайных чисел GMP
        gmp_randstate_t random_state;
        gmp_randinit_default(random_state);
        gmp_randseed(random_state, seed);

        size_t input_length = strlen(params);
        size_t key_length = input_length == 0 ? 16 : input_length;

        if (key_length >= max_size) {
            key_length = max_size - 1;
        }

        mpz_t random_digit;
        mpz_t digit_range;

        mpz_init(random_digit);
        mpz_init_set_ui(digit_range, 10);

        // Создаём числовой ключ, потому что старый Тритемий принимает цифры
        for (size_t index = 0; index < key_length; ++index) {
            mpz_urandomm(random_digit, random_state, digit_range);

            out_buffer[index] =
                static_cast<char>('0' + mpz_get_ui(random_digit));
        }

        out_buffer[key_length] = '\0';
        *written = key_length;

        mpz_clear(random_digit);
        mpz_clear(digit_range);
        gmp_randclear(random_state);
        mpz_clear(seed);

        return CryptoStatus::Success;
    }
}

extern "C" IEncryptionModule* create() {
    return new TrithemiusCipherModule();
}

extern "C" void destroy(IEncryptionModule* module_pointer) {
    delete module_pointer;
}
