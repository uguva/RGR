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
        
        const size_t MAX_RSA_BLOCK_SIZE = 512; // выше некуда)

        if (is_encrypt) {
            // память под худший случай
            *out_size = input_size * MAX_RSA_BLOCK_SIZE;
        } else {

            *out_size = input_size;
        }

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
    
    for (char& c : k) if (c == ',') c = ' ';
    std::istringstream iss(k);
    std::string e_str, n_str;
    if (!(iss >> e_str >> n_str)) return CryptoStatus::InvalidParam;

    mpz_t m, c, e, n;
    mpz_inits(m, c, e, n, NULL);
    if (mpz_set_str(e, e_str.c_str(), 10) != 0 || mpz_set_str(n, n_str.c_str(), 10) != 0) {
        mpz_clears(m, c, e, n, NULL);
        return CryptoStatus::InvalidParam;
    }

    // динамический размер блока в байтах
    size_t bits = mpz_sizeinbase(n, 2);
    size_t bytes_needed = (bits + 7) / 8; // Округление вверх


    if (output.size < input.size * bytes_needed) {
        mpz_clears(m, c, e, n, NULL);
        return CryptoStatus::BufferTooSmall;
    }

    for (size_t i = 0; i < input.size; i++) {
        mpz_set_ui(m, input.data[i]);
        mpz_powm(c, m, e, n); 
        
        // динамический буфер
        std::vector<uint8_t> buffer(bytes_needed, 0);
        size_t count = 0;
        

        mpz_export(buffer.data(), &count, 1, 1, 1, 0, c);
        

        size_t offset = i * bytes_needed;
        if (count < bytes_needed) {
            memcpy(output.data + offset + (bytes_needed - count), buffer.data(), count);
        } else {
            memcpy(output.data + offset, buffer.data(), bytes_needed);
        }
    }
    mpz_clears(m, c, e, n, NULL);
    return CryptoStatus::Success;
    }

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        std::string k(reinterpret_cast<const char*>(key.data), key.size);
        size_t pos = k.find("Private:");
        if (pos != std::string::npos) k = k.substr(pos + 8);
        
        for (char& c : k) if (c == ',') c = ' ';
        std::istringstream iss(k);
        std::string d_str, n_str;
        if (!(iss >> d_str >> n_str)) return CryptoStatus::InvalidParam;

        mpz_t c, m, d, n;
        mpz_inits(c, m, d, n, NULL);
        if (mpz_set_str(d, d_str.c_str(), 10) != 0 || mpz_set_str(n, n_str.c_str(), 10) != 0) {
            mpz_clears(c, m, d, n, NULL);
            return CryptoStatus::InvalidParam;
        }

        size_t bits = mpz_sizeinbase(n, 2);
        size_t bytes_needed = (bits + 7) / 8;

        // Проверка целостности данных
        if (input.size % bytes_needed != 0) {
            mpz_clears(c, m, d, n, NULL);
            return CryptoStatus::InvalidParam;
        }

        if (output.size < input.size / bytes_needed) {
            mpz_clears(c, m, d, n, NULL);
            return CryptoStatus::BufferTooSmall;
        }

        for (size_t i = 0; i < input.size / bytes_needed; i++) {

            std::vector<uint8_t> buffer(bytes_needed);
            memcpy(buffer.data(), input.data + (i * bytes_needed), bytes_needed);
            

            mpz_import(c, bytes_needed, 1, 1, 1, 0, buffer.data());
            mpz_powm(m, c, d, n);
            
            output.data[i] = static_cast<uint8_t>(mpz_get_ui(m));
        }
        mpz_clears(c, m, d, n, NULL);
        return CryptoStatus::Success;
    }
}
