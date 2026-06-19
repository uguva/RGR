#include "blowfish_trithemius.h"
#include "crypto_interface.h"
#include <openssl/blowfish.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstring>

using namespace std;

class BlowfishCipherModule : public IEncryptionModule {
private:
    static constexpr size_t block_size = 8;
    static constexpr size_t max_key_size = 56;

    BF_KEY create_blowfish_key(const string& key_text) const {
        if (key_text.empty()) {
            throw invalid_argument("Ключ Blowfish не может быть пустым");
        }

        if (key_text.size() > max_key_size) {
            throw invalid_argument("Ключ Blowfish должен быть не длиннее 56 байт");
        }

        BF_KEY blowfish_key;
        BF_set_key(&blowfish_key,
                   static_cast<int>(key_text.size()),
                   reinterpret_cast<const unsigned char*>(key_text.data()));

        return blowfish_key;
    }

    vector<uint8_t> add_padding(const vector<uint8_t>& input_data) const {
        vector<uint8_t> padded_data = input_data;
        uint8_t padding_size = static_cast<uint8_t>(block_size - (input_data.size() % block_size));

        if (padding_size == 0) {
            padding_size = block_size;
        }

        for (uint8_t padding_index = 0; padding_index < padding_size; ++padding_index) {
            padded_data.push_back(padding_size);
        }

        return padded_data;
    }

    vector<uint8_t> remove_padding(const vector<uint8_t>& decrypted_data) const {
        if (decrypted_data.empty() || decrypted_data.size() % block_size != 0) {
            throw invalid_argument("Некорректный размер расшифрованных данных");
        }

        uint8_t padding_size = decrypted_data.back();

        if (padding_size == 0 || padding_size > block_size || padding_size > decrypted_data.size()) {
            throw invalid_argument("Некорректное дополнение Blowfish");
        }

        for (size_t padding_index = decrypted_data.size() - padding_size;
             padding_index < decrypted_data.size();
             ++padding_index) {
            if (decrypted_data[padding_index] != padding_size) {
                throw invalid_argument("Некорректное дополнение Blowfish");
            }
        }

        return vector<uint8_t>(decrypted_data.begin(), decrypted_data.end() - padding_size);
    }

public:
    vector<uint8_t> encrypt(const vector<uint8_t>& input_data,
                            const string& key_text) override {
        BF_KEY blowfish_key = create_blowfish_key(key_text);
        vector<uint8_t> padded_data = add_padding(input_data);
        vector<uint8_t> encrypted_data(padded_data.size());

        for (size_t block_offset = 0; block_offset < padded_data.size(); block_offset += block_size) {
            BF_ecb_encrypt(reinterpret_cast<const unsigned char*>(&padded_data[block_offset]),
                           reinterpret_cast<unsigned char*>(&encrypted_data[block_offset]),
                           &blowfish_key,
                           BF_ENCRYPT);
        }

        return encrypted_data;
    }

    vector<uint8_t> decrypt(const vector<uint8_t>& encrypted_data,
                            const string& key_text) override {
        if (encrypted_data.empty() || encrypted_data.size() % block_size != 0) {
            throw invalid_argument("Размер шифротекста Blowfish должен быть кратен 8 байтам");
        }

        BF_KEY blowfish_key = create_blowfish_key(key_text);
        vector<uint8_t> decrypted_data(encrypted_data.size());

        for (size_t block_offset = 0; block_offset < encrypted_data.size(); block_offset += block_size) {
            BF_ecb_encrypt(reinterpret_cast<const unsigned char*>(&encrypted_data[block_offset]),
                           reinterpret_cast<unsigned char*>(&decrypted_data[block_offset]),
                           &blowfish_key,
                           BF_DECRYPT);
        }

        return remove_padding(decrypted_data);
    }

    string get_name() const override {
        return "Blowfish";
    }

    string get_extension() const override {
        return ".enc";
    }
};

static BlowfishCipherModule g_instance;

extern "C" {
    const AlgorithmInfo* get_algorithm_info() {
        static const AlgorithmInfo info = { "Blowfish", 8 };
        return &info;
    }

    CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
        if (is_encrypt) *out_size = input_size + (8 - (input_size % 8));
        else *out_size = input_size;
        return CryptoStatus::Success;
    }

    CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        try {
            std::vector<uint8_t> in_vec(input.data, input.data + input.size);
            std::string key_str(reinterpret_cast<const char*>(key.data), key.size);
            auto res = g_instance.encrypt(in_vec, key_str);
            if (output.size < res.size()) return CryptoStatus::BufferTooSmall;
            std::copy(res.begin(), res.end(), output.data);
            return CryptoStatus::Success;
        } catch (...) { return CryptoStatus::InvalidParam; }
    }

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        try {
            std::vector<uint8_t> in_vec(input.data, input.data + input.size);
            std::string key_str(reinterpret_cast<const char*>(key.data), key.size);
            auto res = g_instance.decrypt(in_vec, key_str);
            if (output.size < res.size()) return CryptoStatus::BufferTooSmall;
            std::copy(res.begin(), res.end(), output.data);
            return CryptoStatus::Success;
        } catch (...) { return CryptoStatus::InvalidParam; }
    }

    CryptoStatus generate_keys(const char* params, char* out_buffer, size_t max_size, size_t* written) {
        if (!params || max_size < 56) return CryptoStatus::BufferTooSmall;

        // Хешируем входную строку для получения уникального seed
        unsigned int seed = 0;
        for(size_t i = 0; params[i] != '\0'; ++i) seed = seed * 131 + (unsigned char)params[i];
        srand(seed);

        // Blowfish: длина ключа от 4 до 56 байт
        size_t input_len = strlen(params);
        size_t key_len = (input_len % 53) + 4; 
        
        // Генерация случайных байтов
        for(size_t i = 0; i < key_len; i++) {
            out_buffer[i] = (char)(rand() % 256);
        }
        
        *written = key_len;
        return CryptoStatus::Success;
    }
}

extern "C" IEncryptionModule* create() {
    return new BlowfishCipherModule();
}

extern "C" void destroy(IEncryptionModule* module_pointer) {
    delete module_pointer;
}
