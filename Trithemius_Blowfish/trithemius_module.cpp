#include "encryption_interface.h"

#include <cstdint>
#include <string>
#include <vector>

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

extern "C" IEncryptionModule* create() {
    return new TrithemiusCipherModule();
}

extern "C" void destroy(IEncryptionModule* module_pointer) {
    delete module_pointer;
}
