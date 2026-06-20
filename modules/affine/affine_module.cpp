#include "crypto_interface.h"
#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <gmp.h>

using namespace std;

namespace {

    int greatest_common_divisor(int first, int second) {
        first = first < 0 ? -first : first;
        second = second < 0 ? -second : second;
        while (second != 0) {
            int remainder = first % second;
            first = second;
            second = remainder;
        }
        return first;
    }

    int modular_inverse_256(int number) {
        if (number % 2 == 0) return -1;
        number = number % 256;
        for (int candidate = 1; candidate < 256; candidate++) {
            if ((number * candidate) % 256 == 1) return candidate;
        }
        return -1;
    }
}

extern "C" {

    const AlgorithmInfo* get_algorithm_info() {
        static const AlgorithmInfo info = { "Affine", 2 };
        return &info;
    }

    CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
        if (!out_size) return CryptoStatus::InvalidParam;
        *out_size = input_size;
        return CryptoStatus::Success;
    }

    CryptoStatus generate_keys(const char* params, char* out_buffer, size_t max_size, size_t* written) {
        srand(static_cast<unsigned>(time(nullptr)));

        int a;
        do {
            a = (rand() % 255) + 1;
        } while (greatest_common_divisor(a, 256) != 1);

        int b = rand() % 256;

        string res = to_string(a) + " " + to_string(b);

        if (res.size() >= max_size) return CryptoStatus::BufferTooSmall;
        strcpy(out_buffer, res.c_str());
        *written = res.size();
        return CryptoStatus::Success;
    }

    CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        string k(reinterpret_cast<const char*>(key.data), key.size);

        mpz_t a, b, p, c, mod;
        mpz_init(a);
        mpz_init(b);
        mpz_init(p);
        mpz_init(c);
        mpz_init_set_ui(mod, 256);

        if (mpz_set_str(a, k.c_str(), 10) != 0) {
            mpz_clear(a); mpz_clear(b); mpz_clear(p); mpz_clear(c); mpz_clear(mod);
            return CryptoStatus::InvalidParam;
        }

        size_t space_pos = k.find(' ');
        if (space_pos == string::npos) {
            mpz_clear(a); mpz_clear(b); mpz_clear(p); mpz_clear(c); mpz_clear(mod);
            return CryptoStatus::InvalidParam;
        }

        string b_str = k.substr(space_pos + 1);
        if (mpz_set_str(b, b_str.c_str(), 10) != 0) {
            mpz_clear(a); mpz_clear(b); mpz_clear(p); mpz_clear(c); mpz_clear(mod);
            return CryptoStatus::InvalidParam;
        }

        if (greatest_common_divisor(mpz_get_ui(a), 256) != 1) {
            mpz_clear(a); mpz_clear(b); mpz_clear(p); mpz_clear(c); mpz_clear(mod);
            return CryptoStatus::InvalidParam;
        }

        if (output.size < input.size) {
            mpz_clear(a); mpz_clear(b); mpz_clear(p); mpz_clear(c); mpz_clear(mod);
            return CryptoStatus::BufferTooSmall;
        }

        for (size_t i = 0; i < input.size; i++) {
            mpz_set_ui(p, input.data[i]);
            mpz_mul(c, a, p);
            mpz_add(c, c, b);
            mpz_mod(c, c, mod);
            output.data[i] = static_cast<uint8_t>(mpz_get_ui(c));
        }

        mpz_clear(a); mpz_clear(b); mpz_clear(p); mpz_clear(c); mpz_clear(mod);
        return CryptoStatus::Success;
    }

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        string k(reinterpret_cast<const char*>(key.data), key.size);

        mpz_t a, b, a_inv, c, p, mod;
        mpz_init(a);
        mpz_init(b);
        mpz_init(a_inv);
        mpz_init(c);
        mpz_init(p);
        mpz_init_set_ui(mod, 256);

        if (mpz_set_str(a, k.c_str(), 10) != 0) {
            mpz_clear(a); mpz_clear(b); mpz_clear(a_inv); mpz_clear(c); mpz_clear(p); mpz_clear(mod);
            return CryptoStatus::InvalidParam;
        }

        size_t space_pos = k.find(' ');
        if (space_pos == string::npos) {
