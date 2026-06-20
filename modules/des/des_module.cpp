#include "crypto_interface.h"
#include <gmp.h>
#include <vector>
#include <array>
#include <string>
#include <random>
#include <cstring>

using namespace std;

namespace {
    constexpr size_t DES_BLOCK_SIZE = 8;
    constexpr size_t DES_KEY_SIZE = 8;
    constexpr uint8_t MAGIC[4] = {'R', 'G', 'Z', '1'};
    constexpr uint8_t VERSION = 1;
    constexpr uint8_t SALT_SIZE = 8;
    constexpr uint8_t IV_SIZE = 8;

    const int IP[64] = {
        58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
        62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
        57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
        61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
    };
    const int FP[64] = {
        40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
        38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
        36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
        34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
    };
    const int E[48] = {
        32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,
        12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,
        24,25,26,27,28,29,28,29,30,31,32,1
    };
    const int P[32] = {
        16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
        2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
    };
    const int PC1[56] = {
        57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,
        59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,
        31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,
        29,21,13,5,28,20,12,4
    };
    const int PC2[48] = {
        14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,
        26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,
        51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32
    };
    const int SHIFTS[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };
    const int SBOX[8][4][16] = {
        {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
        {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
        {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
        {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
        {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
        {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
        {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
        {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
    };

    void init_mpz_array(mpz_t* arr, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            mpz_init(arr[i]);
        }
    }

    void clear_mpz_array(mpz_t* arr, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            mpz_clear(arr[i]);
        }
    }

    void mpz_mask_bits(mpz_t rop, const mpz_t op, unsigned long bits) {
        mpz_fdiv_r_2exp(rop, op, bits);
    }

    void permute(mpz_t output, const mpz_t input, const int* table, int n, int inputBits) {
        mpz_set_ui(output, 0);
        for (int i = 0; i < n; ++i) {
            mpz_mul_2exp(output, output, 1);
            if (mpz_tstbit(input, static_cast<unsigned long>(inputBits - table[i]))) {
                mpz_add_ui(output, output, 1);
            }
        }
    }

    void bytesToMpz(mpz_t value, const uint8_t* data, size_t len) {
        mpz_import(value, len, 1, 1, 1, 0, data);
    }

    void mpzToBytes(const mpz_t value, uint8_t* data, size_t len) {
        memset(data, 0, len);
        size_t count = 0;
        uint8_t tmp[16] = {0};
        mpz_export(tmp, &count, 1, 1, 1, 0, value);
        if (count >= len) {
            memcpy(data, tmp + (count - len), len);
        } else if (count > 0) {
            memcpy(data + (len - count), tmp, count);
        }
    }

    void rotl28(mpz_t out, const mpz_t x, int n) {
        mpz_t left, right;
        mpz_init(left);
        mpz_init(right);
        mpz_mul_2exp(left, x, n);
        mpz_fdiv_r_2exp(left, left, 28);
        mpz_fdiv_q_2exp(right, x, 28 - n);
        mpz_add(out, left, right);
        mpz_fdiv_r_2exp(out, out, 28);
        mpz_clear(left);
        mpz_clear(right);
    }

    void feistel(mpz_t out, const mpz_t right, const mpz_t subkey) {
        mpz_t expanded, sOut, chunk, tmp;
        mpz_init(expanded);
        mpz_init(sOut);
        mpz_init(chunk);
        mpz_init(tmp);

        permute(expanded, right, E, 48, 32);
        mpz_xor(expanded, expanded, subkey);
        mpz_set_ui(sOut, 0);

        for (int box = 0; box < 8; ++box) {
            mpz_fdiv_q_2exp(tmp, expanded, 42 - 6 * box);
            mpz_fdiv_r_2exp(chunk, tmp, 6);
            unsigned long c = mpz_get_ui(chunk);
            int row = static_cast<int>(((c & 0x20) >> 4) | (c & 0x01));
            int col = static_cast<int>((c >> 1) & 0x0F);
            mpz_mul_2exp(sOut, sOut, 4);
            mpz_add_ui(sOut, sOut, static_cast<unsigned long>(SBOX[box][row][col]));
        }

        permute(out, sOut, P, 32, 32);
        mpz_fdiv_r_2exp(out, out, 32);

        mpz_clear(expanded);
        mpz_clear(sOut);
        mpz_clear(chunk);
        mpz_clear(tmp);
    }

    void buildSubKeys(const vector<uint8_t>& key, mpz_t subkeys[16]) {
        mpz_t keyMpz, perm56, c, d, cd, tmp;
        mpz_init(keyMpz);
        mpz_init(perm56);
        mpz_init(c);
        mpz_init(d);
        mpz_init(cd);
        mpz_init(tmp);

        bytesToMpz(keyMpz, key.data(), key.size());
        permute(perm56, keyMpz, PC1, 56, 64);
        mpz_fdiv_q_2exp(c, perm56, 28);
        mpz_fdiv_r_2exp(d, perm56, 28);

        for (int round = 0; round < 16; ++round) {
            rotl28(c, c, SHIFTS[round]);
            rotl28(d, d, SHIFTS[round]);
            mpz_mul_2exp(cd, c, 28);
            mpz_add(cd, cd, d);
            permute(subkeys[round], cd, PC2, 48, 56);
            mpz_fdiv_r_2exp(subkeys[round], subkeys[round], 48);
        }

        mpz_clear(keyMpz);
        mpz_clear(perm56);
        mpz_clear(c);
        mpz_clear(d);
        mpz_clear(cd);
        mpz_clear(tmp);
    }

    void processBlock(mpz_t out, const mpz_t block, mpz_t subkeys[16]) {
        mpz_t b, left, right, temp, f;
        mpz_init(b);
        mpz_init(left);
        mpz_init(right);
        mpz_init(temp);
        mpz_init(f);

        permute(b, block, IP, 64, 64);
        mpz_fdiv_q_2exp(left, b, 32);
        mpz_fdiv_r_2exp(right, b, 32);

        for (int round = 0; round < 16; ++round) {
            mpz_set(temp, right);
            feistel(f, right, subkeys[round]);
            mpz_xor(right, left, f);
            mpz_fdiv_r_2exp(right, right, 32);
            mpz_set(left, temp);
            mpz_fdiv_r_2exp(left, left, 32);
        }

        mpz_mul_2exp(temp, right, 32);
        mpz_add(temp, temp, left);
        permute(out, temp, FP, 64, 64);
        mpz_fdiv_r_2exp(out, out, 64);

        mpz_clear(b);
        mpz_clear(left);
        mpz_clear(right);
        mpz_clear(temp);
        mpz_clear(f);
    }

    vector<uint8_t> deriveKey(const vector<uint8_t>& password, const vector<uint8_t>& salt, size_t keyLen) {
        vector<uint8_t> key(keyLen, 0);
        if (password.empty()) return key;
        for (size_t i = 0; i < keyLen; ++i) {
            uint8_t p = password[i % password.size()], s = salt.empty() ? 0 : salt[i % salt.size()];
            key[i] = static_cast<uint8_t>((p ^ s ^ (i * 17 + 31)) + (i * 13));
        }
        for (int round = 0; round < 1024; ++round) {
            for (size_t i = 0; i < keyLen; ++i) {
                uint8_t p = password[(i + round) % password.size()], s = salt.empty() ? 0 : salt[(i + round) % salt.size()];
                uint8_t x = key[i] ^ p ^ s ^ static_cast<uint8_t>(round + i);
                uint8_t shift = static_cast<uint8_t>((i + round) & 7);
                key[i] = static_cast<uint8_t>((x << shift) | (x >> (8 - shift)));
            }
        }
        return key;
    }

    void pkcs7Pad(vector<uint8_t>& data, size_t blockSize) {
        size_t pad = blockSize - (data.size() % blockSize);
        data.insert(data.end(), pad, static_cast<uint8_t>(pad));
    }
}

extern "C" {
    const AlgorithmInfo* get_algorithm_info() {
        static const AlgorithmInfo info = { "DES", 8 };
        return &info;
    }

    CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
        if (!out_size) return CryptoStatus::InvalidParam;
        if (is_encrypt) {
            size_t padded = input_size + (8 - (input_size % 8));
            *out_size = 24 + padded;
        } else {
            *out_size = input_size > 24 ? input_size - 24 : 0;
        }
        return CryptoStatus::Success;
    }

    CryptoStatus generate_keys(const char* params, char* out_buffer, size_t max_size, size_t* written) {
        static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        (void)params;
        string res;
        random_device rd; mt19937 gen(rd()); uniform_int_distribution<int> dist(0, sizeof(alphanum) - 2);
        for (int i = 0; i < 8; ++i) res += alphanum[dist(gen)];
        if (res.size() + 1 > max_size) return CryptoStatus::BufferTooSmall;
        strcpy(out_buffer, res.c_str());
        if (written) *written = res.size();
        return CryptoStatus::Success;
    }

    CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        if (input.size == 0 || key.size == 0) return CryptoStatus::InvalidParam;

        CryptoStatus status = CryptoStatus::Success;
        vector<uint8_t> pwd(key.data, key.data + key.size), in(input.data, input.data + input.size);
        pkcs7Pad(in, DES_BLOCK_SIZE);

        vector<uint8_t> salt(SALT_SIZE), iv(IV_SIZE);
        random_device rd; mt19937 gen(rd()); uniform_int_distribution<int> dist(0, 255);
        for (size_t i = 0; i < SALT_SIZE; ++i) {
            salt[i] = static_cast<uint8_t>(dist(gen));
            iv[i] = static_cast<uint8_t>(dist(gen));
        }

        vector<uint8_t> derived = deriveKey(pwd, salt, DES_KEY_SIZE);
        mpz_t subkeys[16];
        init_mpz_array(subkeys, 16);
        buildSubKeys(derived, subkeys);

        vector<uint8_t> cipher;
        cipher.insert(cipher.end(), MAGIC, MAGIC + 4);
        cipher.push_back(VERSION);
        cipher.push_back(2);
        cipher.push_back(SALT_SIZE);
        cipher.push_back(IV_SIZE);
        cipher.insert(cipher.end(), salt.begin(), salt.end());
        cipher.insert(cipher.end(), iv.begin(), iv.end());

        array<uint8_t, DES_BLOCK_SIZE> prev{};
        memcpy(prev.data(), iv.data(), IV_SIZE);

        mpz_t blockIn, blockOut;
        mpz_init(blockIn);
        mpz_init(blockOut);

        for (size_t offset = 0; offset < in.size(); offset += DES_BLOCK_SIZE) {
            array<uint8_t, DES_BLOCK_SIZE> block{};
            for (size_t i = 0; i < DES_BLOCK_SIZE; ++i) {
                block[i] = static_cast<uint8_t>(in[offset + i] ^ prev[i]);
            }
            bytesToMpz(blockIn, block.data(), DES_BLOCK_SIZE);
            processBlock(blockOut, blockIn, subkeys);
            mpzToBytes(blockOut, block.data(), DES_BLOCK_SIZE);
            cipher.insert(cipher.end(), block.begin(), block.end());
            prev = block;
        }

        if (output.size < cipher.size()) {
            status = CryptoStatus::BufferTooSmall;
            goto cleanup_encrypt;
        }
        memcpy(output.data, cipher.data(), cipher.size());

    cleanup_encrypt:
        mpz_clear(blockIn);
        mpz_clear(blockOut);
        clear_mpz_array(subkeys, 16);
        return status;
    }

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        if (input.size < 24) return CryptoStatus::InvalidParam;
        if (memcmp(input.data, MAGIC, 4) != 0) return CryptoStatus::InvalidParam;

        CryptoStatus status = CryptoStatus::Success;
        vector<uint8_t> pwd(key.data, key.data + key.size);
        vector<uint8_t> salt(input.data + 8, input.data + 8 + SALT_SIZE);
        vector<uint8_t> iv(input.data + 8 + SALT_SIZE, input.data + 8 + SALT_SIZE + IV_SIZE);
        vector<uint8_t> cipher(input.data + 24, input.data + input.size);

        vector<uint8_t> derived = deriveKey(pwd, salt, DES_KEY_SIZE);
        mpz_t subkeys[16];
        mpz_t rev_subkeys[16];
        init_mpz_array(subkeys, 16);
        init_mpz_array(rev_subkeys, 16);
        buildSubKeys(derived, subkeys);
        for (size_t i = 0; i < 16; ++i) {
            mpz_set(rev_subkeys[i], subkeys[15 - i]);
        }

        vector<uint8_t> plain;
        array<uint8_t, DES_BLOCK_SIZE> prev{};
        memcpy(prev.data(), iv.data(), IV_SIZE);

        mpz_t blockIn, blockOut;
        mpz_init(blockIn);
        mpz_init(blockOut);

        for (size_t pos = 0; pos + DES_BLOCK_SIZE <= cipher.size(); pos += DES_BLOCK_SIZE) {
            array<uint8_t, DES_BLOCK_SIZE> block{}, cipherBlock{};
            memcpy(block.data(), cipher.data() + pos, DES_BLOCK_SIZE);
            memcpy(cipherBlock.data(), cipher.data() + pos, DES_BLOCK_SIZE);

            bytesToMpz(blockIn, block.data(), DES_BLOCK_SIZE);
            processBlock(blockOut, blockIn, rev_subkeys);
            mpzToBytes(blockOut, block.data(), DES_BLOCK_SIZE);

            for (size_t i = 0; i < DES_BLOCK_SIZE; ++i) {
                block[i] = static_cast<uint8_t>(block[i] ^ prev[i]);
            }
            plain.insert(plain.end(), block.begin(), block.end());
            prev = cipherBlock;
        }

        if (plain.empty()) {
            status = CryptoStatus::InvalidParam;
            goto cleanup_decrypt;
        }

        uint8_t pad = plain.back();
        if (pad == 0 || pad > DES_BLOCK_SIZE || pad > plain.size()) {
            status = CryptoStatus::InvalidParam;
            goto cleanup_decrypt;
        }
        plain.resize(plain.size() - pad);

        if (output.size < plain.size()) {
            status = CryptoStatus::BufferTooSmall;
            goto cleanup_decrypt;
        }
        memcpy(output.data, plain.data(), plain.size());

    cleanup_decrypt:
        mpz_clear(blockIn);
        mpz_clear(blockOut);
        clear_mpz_array(subkeys, 16);
        clear_mpz_array(rev_subkeys, 16);
        return status;
    }
}
