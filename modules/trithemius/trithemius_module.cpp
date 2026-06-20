#include "crypto_interface.h"
#include "blowfish_trithemius.h"

#include <cstdint>
#include <string>
#include <vector>
#include <cstring>

using namespace std;

class TrithemiusCipherModule : public IEncryptionModule {
private:
    uint8_t get_initial_shift(const string& key_text) const {
        if (key_text.empty()) {
            return 0;
        }

        int shift_value = 0;
        bool numeric_key_detected = true;

        for (char key_character : key_text) {
            if (key_character < '0' || key_character > '9') {
                numeric_key_detected = false;
                break;
            }
            shift_value = shift_value * 10 + (key_character - '0');
        }

        if (!numeric_key_detected) {
            return 0;
        }

        return static_cast<uint8_t>(shift_value % 256);
    }

public:
    vector<uint8_t> encrypt(const vector<uint8_t>& input_data,
                            const string& key_text) override {
        vector<uint8_t> encrypted_data;
        encrypted_data.reserve(input_data.size());

        uint8_t initial_shift = get_initial_shift(key_text);

        for (size_t byte_index = 0; byte_index < input_data.size(); ++byte_index) {
            uint16_t current_shift = static_cast<uint16_t>(initial_shift) + byte_index;
            uint8_t encrypted_byte = static_cast<uint8_t>((input_data[byte_index] + current_shift) % 256);
            encrypted_data.push_back(encrypted_byte);
        }

        return encrypted_data;
    }

    vector<uint8_t> decrypt(const vector<uint8_t>& encrypted_data,
                            const string& key_text) override {
        vector<uint8_t> decrypted_data;
        decrypted_data.reserve(encrypted_data.size());

        uint8_t initial_shift = get_initial_shift(key_text);

        for (size_t byte_index = 0; byte_index < encrypted_data.size(); ++byte_index) {
            uint16_t current_shift = static_cast<uint16_t>(initial_shift) + byte_index;
            uint8_t decrypted_byte = static_cast<uint8_t>((encrypted_data[byte_index] + 256 - (current_shift % 256)) % 256);
            decrypted_data.push_back(decrypted_byte);
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
        std::vector<uint8_t> in_vec(input.data, input.data + input.size);
        std::string key_str(reinterpret_cast<const char*>(key.data), key.size);
        auto res = g_instance.encrypt(in_vec, key_str);
        if (output.size < res.size()) return CryptoStatus::BufferTooSmall;
        std::copy(res.begin(), res.end(), output.data);
        return CryptoStatus::Success;
    }

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        std::vector<uint8_t> in_vec(input.data, input.data + input.size);
        std::string key_str(reinterpret_cast<const char*>(key.data), key.size);
        auto res = g_instance.decrypt(in_vec, key_str);
        if (output.size < res.size()) return CryptoStatus::BufferTooSmall;
        std::copy(res.begin(), res.end(), output.data);
        return CryptoStatus::Success;
    }

    CryptoStatus generate_keys(const char* params, char* out_buffer, size_t max_size, size_t* written) {
        if (!params || max_size < 1) return CryptoStatus::BufferTooSmall;

        // Хешируем входную строку
        unsigned int seed = 0;
        for(size_t i = 0; params[i] != '\0'; ++i) seed = seed * 131 + (unsigned char)params[i];
        srand(seed);

        // Trithemius: длина ключа равна длине ввода (минимум 8, максимум max_size-1)
        size_t input_len = strlen(params);
        size_t key_len = (input_len == 0) ? 16 : input_len;
        if (key_len >= max_size) key_len = max_size - 1;

        const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for(size_t i = 0; i < key_len; i++) {
            out_buffer[i] = charset[rand() % (sizeof(charset) - 1)];
        }
        
        // Для ASCII-шифров желательно терминировать строку нулем
        out_buffer[key_len] = '\0';
        *written = key_len;
        return CryptoStatus::Success;
    }
}

extern "C" IEncryptionModule* create() {
    return new TrithemiusCipherModule();
}

extern "C" void destroy(IEncryptionModule* module_pointer) {
    delete module_pointer;
}
