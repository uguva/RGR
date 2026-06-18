#include "crypto_interface.h"
#include <gmp.h>
#include <string>
#include <sstream>
#include <cstring>

extern "C" {
    const AlgorithmInfo* get_algorithm_info() {
        static const AlgorithmInfo info = { "RSA", 0 };
        return &info;
    }

    CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
        if (!out_size) return CryptoStatus::InvalidParam;
        *out_size = is_encrypt ? (input_size * 8) : (input_size / 8);
        return CryptoStatus::Success;
    }

    CryptoStatus generate_keys(const char* params, char* out_buffer, size_t max_size, size_t* written) {
        std::istringstream iss(params);
        std::string p_str, q_str;
        if (!(iss >> p_str >> q_str)) return CryptoStatus::InvalidParam;

        mpz_t p, q, n, phi, e, d, p_minus, q_minus, gcd_val;
        mpz_inits(p, q, n, phi, e, d, p_minus, q_minus, gcd_val, NULL);

        if (mpz_set_str(p, p_str.c_str(), 10) != 0 || mpz_set_str(q, q_str.c_str(), 10) != 0) return CryptoStatus::InvalidParam;
        if (mpz_probab_prime_p(p, 25) == 0 || mpz_probab_prime_p(q, 25) == 0) return CryptoStatus::InvalidParam;

        mpz_mul(n, p, q);
        mpz_sub_ui(p_minus, p, 1);
        mpz_sub_ui(q_minus, q, 1);
        mpz_mul(phi, p_minus, q_minus);

        mpz_set_ui(e, 65537);
        mpz_gcd(gcd_val, e, phi);
        if (mpz_cmp_ui(gcd_val, 1) != 0) return CryptoStatus::InvalidParam;
        
        mpz_invert(d, e, phi);

        char e_buf[1024], n_buf[1024], d_buf[1024];
        mpz_get_str(e_buf, 10, e);
        mpz_get_str(n_buf, 10, n);
        mpz_get_str(d_buf, 10, d);

        std::string res = "Public: " + std::string(e_buf) + "," + std::string(n_buf) + "\n" +
                          "Private: " + std::string(d_buf) + "," + std::string(n_buf);
        
        mpz_clears(p, q, n, phi, e, d, p_minus, q_minus, gcd_val, NULL);

        if (res.size() >= max_size) return CryptoStatus::BufferTooSmall;
        strcpy(out_buffer, res.c_str());
        *written = res.size();
        return CryptoStatus::Success;
    }

    CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        std::string k(reinterpret_cast<const char*>(key.data), key.size);
        size_t pos = k.find("Public:");
        if (pos != std::string::npos) k = k.substr(pos + 7);
        
        for (char& c : k) if (c == ',') c = ' '; // Заменяем запятую на пробел для sstream
        std::istringstream iss(k);
        std::string e_str, n_str;
        if (!(iss >> e_str >> n_str)) return CryptoStatus::InvalidParam;

        mpz_t m, c, e, n;
        mpz_inits(m, c, e, n, NULL);
        if (mpz_set_str(e, e_str.c_str(), 10) != 0 || mpz_set_str(n, n_str.c_str(), 10) != 0) return CryptoStatus::InvalidParam;

        if (output.size < input.size * 8) return CryptoStatus::BufferTooSmall;

        for (size_t i = 0; i < input.size; i++) {
            mpz_set_ui(m, input.data[i]);
            mpz_powm(c, m, e, n); // c = (m^e) mod n
            
            // Экспортируем результат в 8 байт (Little Endian формат)
            uint8_t buffer[8] = {0};
            size_t count = 0;
            mpz_export(buffer, &count, -1, 1, 0, 0, c);
            memcpy(output.data + (i * 8), buffer, 8);
        }
        mpz_clears(m, c, e, n, NULL);
        return CryptoStatus::Success;
    }

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        if (input.size % 8 != 0) return CryptoStatus::InvalidParam;

        std::string k(reinterpret_cast<const char*>(key.data), key.size);
        size_t pos = k.find("Private:");
        if (pos != std::string::npos) k = k.substr(pos + 8);
        
        for (char& c : k) if (c == ',') c = ' ';
        std::istringstream iss(k);
        std::string d_str, n_str;
        if (!(iss >> d_str >> n_str)) return CryptoStatus::InvalidParam;

        mpz_t c, m, d, n;
        mpz_inits(c, m, d, n, NULL);
        if (mpz_set_str(d, d_str.c_str(), 10) != 0 || mpz_set_str(n, n_str.c_str(), 10) != 0) return CryptoStatus::InvalidParam;

        if (output.size < input.size / 8) return CryptoStatus::BufferTooSmall;

        for (size_t i = 0; i < input.size / 8; i++) {
            uint8_t buffer[8];
            memcpy(buffer, input.data + (i * 8), 8);
            
            // Импортируем из 8 байт (Little Endian формат)
            mpz_import(c, 8, -1, 1, 0, 0, buffer);
            mpz_powm(m, c, d, n);
            
            output.data[i] = static_cast<uint8_t>(mpz_get_ui(m));
        }
        mpz_clears(c, m, d, n, NULL);
        return CryptoStatus::Success;
    }
}
