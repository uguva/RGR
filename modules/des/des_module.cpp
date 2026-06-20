#include "crypto_interface.h"
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

    // Классические конфигурационные матрицы перестановок DES
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

    uint64_t permute(uint64_t input, const int* table, int n, int inputBits) {
        uint64_t output = 0;
        for (int i = 0; i < n; ++i) {
            output <<= 1;
            output |= (input >> (inputBits - table[i])) & 1ULL;
        }
        return output;
    }
    uint32_t permute32(uint32_t input, const int* table, int n) { return static_cast<uint32_t>(permute(input, table, n, 32)); }
    uint64_t bytesToU64(const uint8_t* data) {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | data[i];
        return v;
    }
    void u64ToBytes(uint64_t value, uint8_t* data) {
        for (int i = 7; i >= 0; --i) { data[i] = value & 0xFF; value >>= 8; }
    }
    uint32_t rotl28(uint32_t x, int n) { return ((x << n) | (x >> (28 - n))) & 0x0FFFFFFF; }

    uint32_t feistel(uint32_t right, uint64_t subkey) {
        uint64_t expanded = permute(right, E, 48, 32) ^ subkey;
        uint32_t sOut = 0;
        for (int box = 0; box < 8; ++box) {
            uint8_t chunk = (expanded >> (42 - 6 * box)) & 0x3F;
            int row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
            int col = (chunk >> 1) & 0x0F;
            sOut = (sOut << 4) | SBOX[box][row][col];
        }
        return permute32(sOut, P, 32);
    }

    array<uint64_t, 16> buildSubKeys(const vector<uint8_t>& key) {
        array<uint64_t, 16> subkeys{};
        uint64_t key64 = bytesToU64(key.data());
        uint64_t perm56 = permute(key64, PC1, 56, 64);
        uint32_t c = (perm56 >> 28) & 0x0FFFFFFF, d = perm56 & 0x0FFFFFFF;
        for (int round = 0; round < 16; ++round) {
            c = rotl28(c, SHIFTS[round]); d = rotl28(d, SHIFTS[round]);
            subkeys[round] = permute(((static_cast<uint64_t>(c) << 28) | d), PC2, 48, 56);
        }
        return subkeys;
    }

    uint64_t processBlock(uint64_t block, const array<uint64_t, 16>& subkeys) {
        block = permute(block, IP, 64, 64);
        uint32_t left = block >> 32, right = block & 0xFFFFFFFFULL;
        for (int round = 0; round < 16; ++round) {
            uint32_t temp = right;
            right = left ^ feistel(right, subkeys[round]);
            left = temp;
        }
        return permute(((static_cast<uint64_t>(right) << 32) | left), FP, 64, 64);
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
                key[i] = (x << ((i + round) & 7)) | (x >> (8 - ((i + round) & 7)));
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
            *out_size = 24 + padded; // Header(8) + Salt(8) + IV(8) + Padded Data
        } else {
            *out_size = input_size > 24 ? input_size - 24 : 0;
        }
        return CryptoStatus::Success;
    }

    CryptoStatus generate_keys(const char* params, char* out_buffer, size_t max_size, size_t* written) {
        static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        string res = "";
        random_device rd; mt19937 gen(rd()); uniform_int_distribution<int> dist(0, sizeof(alphanum) - 2);
        for (int i = 0; i < 8; ++i) res += alphanum[dist(gen)];
        if (res.size() >= max_size) return CryptoStatus::BufferTooSmall;
        strcpy(out_buffer, res.c_str());
        *written = res.size();
        return CryptoStatus::Success;
    }

    CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        if (input.size == 0 || key.size == 0) return CryptoStatus::InvalidParam;
        vector<uint8_t> pwd(key.data, key.data + key.size), in(input.data, input.data + input.size);
        pkcs7Pad(in, DES_BLOCK_SIZE);

        vector<uint8_t> salt(SALT_SIZE), iv(IV_SIZE);
        random_device rd; mt19937 gen(rd()); uniform_int_distribution<int> dist(0, 255);
        for (size_t i = 0; i < SALT_SIZE; ++i) { salt[i] = dist(gen); iv[i] = dist(gen); }

        vector<uint8_t> derived = deriveKey(pwd, salt, DES_KEY_SIZE);
        array<uint64_t, 16> subkeys = buildSubKeys(derived);

        vector<uint8_t> cipher;
        cipher.insert(cipher.end(), MAGIC, MAGIC + 4);
        cipher.push_back(VERSION); cipher.push_back(2); // 2 = DES
        cipher.push_back(SALT_SIZE); cipher.push_back(IV_SIZE);
        cipher.insert(cipher.end(), salt.begin(), salt.end());
        cipher.insert(cipher.end(), iv.begin(), iv.end());

        array<uint8_t, DES_BLOCK_SIZE> prev{};
        memcpy(prev.data(), iv.data(), IV_SIZE);

        for (size_t offset = 0; offset < in.size(); offset += DES_BLOCK_SIZE) {
            array<uint8_t, DES_BLOCK_SIZE> block{};
            for (size_t i = 0; i < DES_BLOCK_SIZE; ++i) block[i] = in[offset + i] ^ prev[i];
            uint64_t b64 = processBlock(bytesToU64(block.data()), subkeys);
            u64ToBytes(b64, block.data());
            cipher.insert(cipher.end(), block.begin(), block.end());
            prev = block;
        }

        if (output.size < cipher.size()) return CryptoStatus::BufferTooSmall;
        memcpy(output.data, cipher.data(), cipher.size());
        return CryptoStatus::Success;
    }

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        if (input.size < 24) return CryptoStatus::InvalidParam;
        if (memcmp(input.data, MAGIC, 4) != 0) return CryptoStatus::InvalidParam;

        vector<uint8_t> pwd(key.data, key.data + key.size);
        vector<uint8_t> salt(input.data + 8, input.data + 8 + SALT_SIZE);
        vector<uint8_t> iv(input.data + 8 + SALT_SIZE, input.data + 8 + SALT_SIZE + IV_SIZE);
        vector<uint8_t> cipher(input.data + 24, input.data + input.size);

        vector<uint8_t> derived = deriveKey(pwd, salt, DES_KEY_SIZE);
        array<uint64_t, 16> subkeys = buildSubKeys(derived);
        array<uint64_t, 16> rev_subkeys{};
        for (size_t i = 0; i < 16; ++i) rev_subkeys[i] = subkeys[15 - i];

        vector<uint8_t> plain;
        array<uint8_t, DES_BLOCK_SIZE> prev{};
        memcpy(prev.data(), iv.data(), IV_SIZE);

        for (size_t pos = 0; pos < cipher.size(); pos += DES_BLOCK_SIZE) {
            array<uint8_t, DES_BLOCK_SIZE> block{}, cipherBlock{};
            memcpy(block.data(), cipher.data() + pos, DES_BLOCK_SIZE);
            memcpy(cipherBlock.data(), cipher.data() + pos, DES_BLOCK_SIZE);

            uint64_t b64 = processBlock(bytesToU64(block.data()), rev_subkeys);
            u64ToBytes(b64, block.data());

            for (size_t i = 0; i < DES_BLOCK_SIZE; ++i) block[i] ^= prev[i];
            plain.insert(plain.end(), block.begin(), block.end());
            prev = cipherBlock;
        }

        uint8_t pad = plain.back();
        if (pad == 0 || pad > DES_BLOCK_SIZE || pad > plain.size()) return CryptoStatus::InvalidParam;
        plain.resize(plain.size() - pad);

        if (output.size < plain.size()) return CryptoStatus::BufferTooSmall;
        memcpy(output.data, plain.data(), plain.size());
        return CryptoStatus::Success;
    }
}
