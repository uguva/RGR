#include "../../include/encryption_interface.h"
#include <sstream>

using namespace std;

class DiffieHellmanModule : public IEncryptionModule {
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
        uint64_t g = 5;
        uint64_t p = 23;
        uint64_t private_key = 6;

        if (!password.empty()) {
            stringstream ss(password);
            ss >> g >> p >> private_key;
        }

        uint64_t public_component = power_modulo(g, private_key, p);
        
        vector<uint8_t> result;
        result.push_back(static_cast<uint8_t>(public_component & 0xFF));
        result.push_back(static_cast<uint8_t>((public_component >> 8) & 0xFF));
        return result;
    }

    vector<uint8_t> decrypt(const vector<uint8_t>& cipher, const string& password) override {
        uint64_t enemy_public = 0;
        uint64_t private_key = 6;
        uint64_t p = 23;

        if (cipher.size() >= 2) {
            enemy_public = cipher[0] | (static_cast<uint64_t>(cipher[1]) << 8);
        }

        if (!password.empty()) {
            stringstream ss(password);
            ss >> private_key >> p;
        }

        uint64_t shared_secret = power_modulo(enemy_public, private_key, p);

        vector<uint8_t> result;
        result.push_back(static_cast<uint8_t>(shared_secret & 0xFF));
        result.push_back(static_cast<uint8_t>((shared_secret >> 8) & 0xFF));
        return result;
    }

    string get_extension() const override {
        return ".dh";
    }

    string get_name() const override {
        return "DiffieHellman";
    }
};

extern "C" IEncryptionModule* create_module() {
    return new DiffieHellmanModule();
}

extern "C" void destroy_module(IEncryptionModule* module) {
    delete module;
}
