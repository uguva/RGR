#include "crypto_interface.h"
#include <cstdio>
#include <string>
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

uint64_t power_mod(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t res = 1;
    base %= mod;
    while (exp > 0) {
        if (exp % 2 == 1) res = (static_cast<__uint128_t>(res) * base) % mod;
        base = (static_cast<__uint128_t>(base) * base) % mod;
        exp >>= 1;
    }
    return res;
}

extern "C" {
    const AlgorithmInfo* get_algorithm_info() {
        static const AlgorithmInfo info = { "DiffieHellman", 0 };
        return &info;
    }

    CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
        if (!out_size) return CryptoStatus::InvalidParam;
        *out_size = input_size;
        return CryptoStatus::Success;
    }

    CryptoStatus generate_keys(const char* params, char* out_buffer, size_t max_size, size_t* written) {
        uint64_t g, p, a;
        if (sscanf(params, "%lu %lu %lu", &g, &p, &a) != 3) return CryptoStatus::InvalidParam;
        if (!is_prime(p)) return CryptoStatus::InvalidParam;
        uint64_t A = power_mod(g, a, p);
        std::string res = std::to_string(A);
        if (res.size() >= max_size) return CryptoStatus::BufferTooSmall;
        strcpy(out_buffer, res.c_str());
        *written = res.size();
        return CryptoStatus::Success;
    }

    CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        std::string k(reinterpret_cast<const char*>(key.data), key.size);
        uint64_t p = 0, g = 0, priv = 0, pub_enemy = 0;

        if (sscanf(k.c_str(), "%lu %lu %lu %lu", &p, &g, &priv, &pub_enemy) != 4) return CryptoStatus::InvalidParam;
        if (p == 0) return CryptoStatus::InvalidParam;

        uint64_t S = power_mod(pub_enemy, priv, p);
        for (size_t i = 0; i < input.size; ++i) {
            output.data[i] = input.data[i] ^ (static_cast<uint8_t>(S & 0xFF));
        }
        return CryptoStatus::Success;
    }

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        return encrypt(input, key, output);
    }
}
