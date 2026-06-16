#include "../../include/encryption_interface.h"
#include <cmath>
#include <sstream>

using namespace std;

class RSAModule : public IEncryptionModule {
private:
uint64_t power_modulo(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (uint64_t)(((__uint128_t)result * base) % mod);
        }
        base = (uint64_t)(((__uint128_t)base * base) % mod);
        exp /= 2;
    }
    return result;
}

public:
    vector<uint8_t> encrypt(const vector<uint8_t>& payload, const string& password) override {
        uint64_t e = 7;
        uint64_t n = 3233;
        
        if (!password.empty()) {
            stringstream ss(password);
            ss >> e >> n;
        }

        vector<uint8_t> result;
        for (uint8_t byte : payload) {
            uint64_t encrypted_val = power_modulo(byte, e, n);
            result.push_back(static_cast<uint8_t>(encrypted_val & 0xFF));
            result.push_back(static_cast<uint8_t>((encrypted_val >> 8) & 0xFF));
        }
        return result;
    }

    vector<uint8_t> decrypt(const vector<uint8_t>& cipher, const string& password) override {
        uint64_t d = 1783;
        uint64_t n = 3233;

        if (!password.empty()) {
            stringstream ss(password);
            ss >> d >> n;
        }

        vector<uint8_t> result;
        for (size_t i = 0; i < cipher.size(); i += 2) {
            if (i + 1 >= cipher.size()) break;
            uint64_t encrypted_val = cipher[i] | (static_cast<uint64_t>(cipher[i + 1]) << 8);
            uint64_t decrypted_val = power_modulo(encrypted_val, d, n);
            result.push_back(static_cast<uint8_t>(decrypted_val & 0xFF));
        }
        return result;
    }

    string get_extension() const override {
        return ".rsa";
    }

    string get_name() const override {
        return "RSA";
    }
};

extern "C" IEncryptionModule* create_module() {
    return new RSAModule();
}

extern "C" void destroy_module(IEncryptionModule* module) {
    delete module;
}
