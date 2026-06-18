#include "crypto_interface.h"
#include <gmp.h>
#include <string>
#include <sstream>
#include <cstring>

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
        std::istringstream iss(params);
        std::string g_s, p_s, a_s;
        if (!(iss >> g_s >> p_s >> a_s)) return CryptoStatus::InvalidParam;

        mpz_t g, p, a, A;
        mpz_inits(g, p, a, A, NULL);
        
        if (mpz_set_str(g, g_s.c_str(), 10) != 0 || mpz_set_str(p, p_s.c_str(), 10) != 0 || mpz_set_str(a, a_s.c_str(), 10) != 0) {
            return CryptoStatus::InvalidParam;
        }
        if (mpz_probab_prime_p(p, 25) == 0) return CryptoStatus::InvalidParam;

        mpz_powm(A, g, a, p);

        char A_buf[1024];
        mpz_get_str(A_buf, 10, A);
        std::string res(A_buf);
        
        mpz_clears(g, p, a, A, NULL);

        if (res.size() >= max_size) return CryptoStatus::BufferTooSmall;
        strcpy(out_buffer, res.c_str());
        *written = res.size();
        return CryptoStatus::Success;
    }

    CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        std::string k(reinterpret_cast<const char*>(key.data), key.size);
        std::istringstream iss(k);
        std::string p_s, g_s, priv_s, pub_enemy_s;
        
        if (!(iss >> p_s >> g_s >> priv_s >> pub_enemy_s)) return CryptoStatus::InvalidParam;

        mpz_t p, pub_enemy, priv, S;
        mpz_inits(p, pub_enemy, priv, S, NULL);
        
        if (mpz_set_str(p, p_s.c_str(), 10) != 0 || mpz_set_str(pub_enemy, pub_enemy_s.c_str(), 10) != 0 || mpz_set_str(priv, priv_s.c_str(), 10) != 0) {
            return CryptoStatus::InvalidParam;
        }

        mpz_powm(S, pub_enemy, priv, p);
        uint8_t secret_byte = static_cast<uint8_t>(mpz_get_ui(S) & 0xFF);
        mpz_clears(p, pub_enemy, priv, S, NULL);

        for (size_t i = 0; i < input.size; ++i) {
            output.data[i] = input.data[i] ^ secret_byte;
        }
        return CryptoStatus::Success;
    }

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        return encrypt(input, key, output);
    }
}
