#include "crypto_interface.h"
#include <cstdio>
#include <string>
#include <algorithm>
#include <cstring>

bool is_prime(uint64_t n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    for (uint64_t i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return false;
    }
    return true;
}

uint64_t modular_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    if (mod == 1) return 0;
    uint64_t res = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) res = (static_cast<__uint128_t>(res) * base) % mod;
        exp >>= 1;
        base = (static_cast<__uint128_t>(base) * base) % mod;
    }
    return res;
}

extern "C" {
    const AlgorithmInfo* get_algorithm_info() {
        static const AlgorithmInfo info = { "RSA", 0 };
        return &info;
    }

    CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
        if (!out_size) return CryptoStatus::InvalidParam;
        *out_size = is_encrypt ? (input_size * sizeof(uint64_t)) : (input_size / sizeof(uint64_t));
        return CryptoStatus::Success;
    }

    CryptoStatus generate_keys(const char* params, char* out_buffer, size_t max_size, size_t* written) {
        uint64_t p, q;
        if (sscanf(params, "%lu %lu", &p, &q) != 2) return CryptoStatus::InvalidParam;
        if (!is_prime(p) || !is_prime(q)) return CryptoStatus::InvalidParam;
        
        uint64_t n = p * q;
        uint64_t phi = (p - 1) * (q - 1);
        uint64_t e = 65537;
        
        uint64_t gcd_val = phi, temp_e = e;
        while (temp_e) {
            uint64_t temp = temp_e;
            temp_e = gcd_val % temp_e;
            gcd_val = temp;
        }
        if (gcd_val != 1) return CryptoStatus::InvalidParam;

        __int128 signed_phi = phi;
        __int128 signed_e = e;
        __int128 y = 0, x = 1;
        while (signed_e > 1) {
            __int128 q_val = signed_e / signed_phi;
            __int128 t_val = signed_phi;
            signed_phi = signed_e % signed_phi;
            signed_e = t_val;
            t_val = y;
            y = x - q_val * y;
            x = t_val;
        }
        if (x < 0) x += phi;
        uint64_t d = static_cast<uint64_t>(x);

        std::string res = "Public: " + std::to_string(e) + "," + std::to_string(n) + "\nPrivate: " + std::to_string(d) + "," + std::to_string(n);
        if (res.size() >= max_size) return CryptoStatus::BufferTooSmall;
        strcpy(out_buffer, res.c_str());
        *written = res.size();
        return CryptoStatus::Success;
    }

    CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        std::string k(reinterpret_cast<const char*>(key.data), key.size);
        uint64_t e = 0, n = 0;
        
        size_t pos = k.find("Public:");
        if (pos != std::string::npos) {
            if (sscanf(k.c_str() + pos, "Public: %lu,%lu", &e, &n) != 2) return CryptoStatus::InvalidParam;
        } else {
            if (sscanf(k.c_str(), "%lu,%lu", &e, &n) != 2 && sscanf(k.c_str(), "%lu %lu", &e, &n) != 2) {
                return CryptoStatus::InvalidParam;
            }
        }
        
        if (e == 0 || n == 0) return CryptoStatus::InvalidParam;
        if (output.size < input.size * sizeof(uint64_t)) return CryptoStatus::BufferTooSmall;

        for(size_t i = 0; i < input.size; i++) {
            uint64_t cipher_val = modular_pow(input.data[i], e, n);
            memcpy(output.data + (i * sizeof(uint64_t)), &cipher_val, sizeof(uint64_t));
        }
        return CryptoStatus::Success;
    }

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        if (input.size % sizeof(uint64_t) != 0) return CryptoStatus::InvalidParam;

        std::string k(reinterpret_cast<const char*>(key.data), key.size);
        uint64_t d = 0, n = 0;
        
        size_t pos = k.find("Private:");
        if (pos != std::string::npos) {
            if (sscanf(k.c_str() + pos, "Private: %lu,%lu", &d, &n) != 2) return CryptoStatus::InvalidParam;
        } else {
            if (sscanf(k.c_str(), "%lu,%lu", &d, &n) != 2 && sscanf(k.c_str(), "%lu %lu", &d, &n) != 2) {
                return CryptoStatus::InvalidParam;
            }
        }
        
        if (d == 0 || n == 0) return CryptoStatus::InvalidParam;
        if (output.size < input.size / sizeof(uint64_t)) return CryptoStatus::BufferTooSmall;

        for(size_t i = 0; i < input.size / sizeof(uint64_t); i++) {
            uint64_t cipher_val;
            memcpy(&cipher_val, input.data + (i * sizeof(uint64_t)), sizeof(uint64_t));
            output.data[i] = static_cast<uint8_t>(modular_pow(cipher_val, d, n));
        }
        return CryptoStatus::Success;
    }
}
