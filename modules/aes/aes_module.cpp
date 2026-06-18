#include "crypto_interface.h"
#include <vector>
#include <array>
#include <string>
#include <random>
#include <cstring>
#include <stdexcept>

using namespace std;

// === Математика AES (взята из кода одногруппников) ===
namespace {
    constexpr size_t AES_BLOCK_SIZE = 16;
    constexpr size_t AES_KEY_SIZE = 16;
    constexpr size_t AES_ROUNDS = 10;
    constexpr uint8_t MAGIC[4] = {'R', 'G', 'Z', '1'};
    constexpr uint8_t VERSION = 1;
    constexpr uint8_t SALT_SIZE = 16;
    constexpr uint8_t IV_SIZE = 16;

    uint8_t xtime(uint8_t x) { return static_cast<uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00)); }
    uint8_t gfMul(uint8_t a, uint8_t b) {
        uint8_t result = 0;
        while (b) { if (b & 1) result ^= a; a = xtime(a); b >>= 1; }
        return result;
    }
    uint8_t gfPow(uint8_t a, int e) {
        uint8_t result = 1;
        while (e > 0) { if (e & 1) result = gfMul(result, a); a = gfMul(a, a); e >>= 1; }
        return result;
    }
    uint8_t rotl8(uint8_t x, unsigned int n) {
        n &= 7U; if (n == 0) return x;
        return static_cast<uint8_t>((x << n) | (x >> (8U - n)));
    }
    uint8_t aesSBox(uint8_t x) {
        uint8_t inv = (x == 0) ? 0 : gfPow(x, 254);
        return static_cast<uint8_t>(inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63);
    }
    uint8_t aesInvSBox(uint8_t x) {
        static array<uint8_t, 256> invTable{};
        static bool initialized = false;
        if (!initialized) {
            for (int i = 0; i < 256; ++i) invTable[aesSBox(static_cast<uint8_t>(i))] = static_cast<uint8_t>(i);
            initialized = true;
        }
        return invTable[x];
    }
    uint8_t rconValue(size_t round) {
        uint8_t c = 1;
        for (size_t i = 1; i < round; ++i) c = gfMul(c, 2);
        return c;
    }

    void subBytes(array<uint8_t, 16>& state) { for (auto& b : state) b = aesSBox(b); }
    void invSubBytes(array<uint8_t, 16>& state) { for (auto& b : state) b = aesInvSBox(b); }

    void shiftRows(array<uint8_t, 16>& state) {
        array<uint8_t, 16> t = state;
        state[0]=t[0]; state[1]=t[5]; state[2]=t[10]; state[3]=t[15];
        state[4]=t[4]; state[5]=t[9]; state[6]=t[14]; state[7]=t[3];
        state[8]=t[8]; state[9]=t[13]; state[10]=t[2]; state[11]=t[7];
        state[12]=t[12]; state[13]=t[1]; state[14]=t[6]; state[15]=t[11];
    }
    void invShiftRows(array<uint8_t, 16>& state) {
        array<uint8_t, 16> t = state;
        state[0]=t[0]; state[1]=t[13]; state[2]=t[10]; state[3]=t[7];
        state[4]=t[4]; state[5]=t[1]; state[6]=t[14]; state[7]=t[11];
        state[8]=t[8]; state[9]=t[5]; state[10]=t[2]; state[11]=t[15];
        state[12]=t[12]; state[13]=t[9]; state[14]=t[6]; state[15]=t[3];
    }

    void mixColumns(array<uint8_t, 16>& state) {
        for (int c = 0; c < 4; ++c) {
            uint8_t a0 = state[c * 4 + 0], a1 = state[c * 4 + 1], a2 = state[c * 4 + 2], a3 = state[c * 4 + 3];
            state[c * 4 + 0] = static_cast<uint8_t>(gfMul(a0, 2) ^ gfMul(a1, 3) ^ a2 ^ a3);
            state[c * 4 + 1] = static_cast<uint8_t>(a0 ^ gfMul(a1, 2) ^ gfMul(a2, 3) ^ a3);
            state[c * 4 + 2] = static_cast<uint8_t>(a0 ^ a1 ^ gfMul(a2, 2) ^ gfMul(a3, 3));
            state[c * 4 + 3] = static_cast<uint8_t>(gfMul(a0, 3) ^ a1 ^ a2 ^ gfMul(a3, 2));
        }
    }
    void invMixColumns(array<uint8_t, 16>& state) {
        for (int c = 0; c < 4; ++c) {
            uint8_t a0 = state[c * 4 + 0], a1 = state[c * 4 + 1], a2 = state[c * 4 + 2], a3 = state[c * 4 + 3];
            state[c * 4 + 0] = static_cast<uint8_t>(gfMul(a0, 14) ^ gfMul(a1, 11) ^ gfMul(a2, 13) ^ gfMul(a3, 9));
            state[c * 4 + 1] = static_cast<uint8_t>(gfMul(a0, 9)  ^ gfMul(a1, 14) ^ gfMul(a2, 11) ^ gfMul(a3, 13));
            state[c * 4 + 2] = static_cast<uint8_t>(gfMul(a0, 13) ^ gfMul(a1, 9)  ^ gfMul(a2, 14) ^ gfMul(a3, 11));
            state[c * 4 + 3] = static_cast<uint8_t>(gfMul(a0, 11) ^ gfMul(a1, 13) ^ gfMul(a2, 9)  ^ gfMul(a3, 14));
        }
    }

    void addRoundKey(array<uint8_t, 16>& state, const array<uint8_t, 176>& roundKeys, size_t round) {
        for (size_t i = 0; i < AES_BLOCK_SIZE; ++i) state[i] ^= roundKeys[round * AES_BLOCK_SIZE + i];
    }

    array<uint8_t, 176> expandKey(const vector<uint8_t>& key) {
        array<uint8_t, 176> roundKeys{};
        for (size_t i = 0; i < AES_KEY_SIZE; ++i) roundKeys[i] = key[i];
        size_t bytesGenerated = AES_KEY_SIZE;
        size_t rconIteration = 1;
        uint8_t temp[4];
        while (bytesGenerated < roundKeys.size()) {
            for (size_t i = 0; i < 4; ++i) temp[i] = roundKeys[bytesGenerated - 4 + i];
            if (bytesGenerated % AES_KEY_SIZE == 0) {
                uint8_t t = temp[0]; temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
                for (auto& b : temp) b = aesSBox(b);
                temp[0] ^= rconValue(rconIteration++);
            }
            for (size_t i = 0; i < 4; ++i) {
                roundKeys[bytesGenerated] = static_cast<uint8_t>(roundKeys[bytesGenerated - AES_KEY_SIZE] ^ temp[i]);
                ++bytesGenerated;
            }
        }
        return roundKeys;
    }

    array<uint8_t, 16> encryptBlock(array<uint8_t, 16> block, const array<uint8_t, 176>& roundKeys) {
        addRoundKey(block, roundKeys, 0);
        for (size_t round = 1; round < AES_ROUNDS; ++round) {
            subBytes(block); shiftRows(block); mixColumns(block); addRoundKey(block, roundKeys, round);
        }
        subBytes(block); shiftRows(block); addRoundKey(block, roundKeys, AES_ROUNDS);
        return block;
    }

    array<uint8_t, 16> decryptBlock(array<uint8_t, 16> block, const array<uint8_t, 176>& roundKeys) {
        addRoundKey(block, roundKeys, AES_ROUNDS);
        for (int round = static_cast<int>(AES_ROUNDS) - 1; round >= 1; --round) {
            invShiftRows(block); invSubBytes(block); addRoundKey(block, roundKeys, static_cast<size_t>(round)); invMixColumns(block);
        }
        invShiftRows(block); invSubBytes(block); addRoundKey(block, roundKeys, 0);
        return block;
    }

    vector<uint8_t> deriveKey(const vector<uint8_t>& password, const vector<uint8_t>& salt, size_t keyLen) {
        vector<uint8_t> key(keyLen, 0);
        if (password.empty()) return key;
        for (size_t i = 0; i < keyLen; ++i) {
            uint8_t p = password[i % password.size()];
            uint8_t s = salt.empty() ? 0 : salt[i % salt.size()];
            key[i] = static_cast<uint8_t>((p ^ s ^ static_cast<uint8_t>(i * 17 + 31)) + static_cast<uint8_t>(i * 13));
        }
        for (int round = 0; round < 1024; ++round) {
            for (size_t i = 0; i < keyLen; ++i) {
                uint8_t p = password[(i + round) % password.size()];
                uint8_t s = salt.empty() ? 0 : salt[(i + round) % salt.size()];
                uint8_t x = static_cast<uint8_t>(key[i] ^ p ^ s ^ static_cast<uint8_t>(round + i));
                key[i] = static_cast<uint8_t>((x << ((i + round) & 7)) | (x >> (8 - ((i + round) & 7))));
            }
        }
        return key;
    }

    vector<uint8_t> makeRandomBytes(size_t count) {
        vector<uint8_t> result(count);
        random_device rd; mt19937 gen(rd()); uniform_int_distribution<int> dist(0, 255);
        for (size_t i = 0; i < count; ++i) result[i] = static_cast<uint8_t>(dist(gen));
        return result;
    }

    void pkcs7Pad(vector<uint8_t>& data, size_t blockSize) {
        size_t pad = blockSize - (data.size() % blockSize);
        if (pad == 0) pad = blockSize;
        data.insert(data.end(), pad, static_cast<uint8_t>(pad));
    }
}

// === Интерфейс Плагина (Взаимодействие с вашей архитектурой) ===
extern "C" {
    const AlgorithmInfo* get_algorithm_info() {
        static const AlgorithmInfo info = { "AES", 16 };
        return &info;
    }

    CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
        if (!out_size) return CryptoStatus::InvalidParam;
        if (is_encrypt) {
            // Header (8) + Salt (16) + IV (16) + Input + Padding (1-16 bytes)
            size_t padded_size = input_size + (16 - (input_size % 16));
            if (padded_size == input_size) padded_size += 16;
            *out_size = 40 + padded_size;
        } else {
            *out_size = input_size > 40 ? input_size - 40 : 0;
        }
        return CryptoStatus::Success;
    }

    CryptoStatus generate_keys(const char* params, char* out_buffer, size_t max_size, size_t* written) {
        // Для AES ключ - это просто строка (пароль). Сгенерируем случайный 16-символьный пароль.
        static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        std::string res = "";
        random_device rd; mt19937 gen(rd()); uniform_int_distribution<int> dist(0, sizeof(alphanum) - 2);
        for (int i = 0; i < 16; ++i) res += alphanum[dist(gen)];
        
        if (res.size() >= max_size) return CryptoStatus::BufferTooSmall;
        strcpy(out_buffer, res.c_str());
        *written = res.size();
        return CryptoStatus::Success;
    }

    CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        if (input.size == 0 || key.size == 0) return CryptoStatus::InvalidParam;
        
        vector<uint8_t> password(key.data, key.data + key.size);
        vector<uint8_t> in_data(input.data, input.data + input.size);
        pkcs7Pad(in_data, AES_BLOCK_SIZE);

        vector<uint8_t> salt = makeRandomBytes(SALT_SIZE);
        vector<uint8_t> iv = makeRandomBytes(IV_SIZE);
        vector<uint8_t> derived_key = deriveKey(password, salt, AES_KEY_SIZE);
        array<uint8_t, 176> roundKeys = expandKey(derived_key);

        vector<uint8_t> cipher;
        cipher.reserve(40 + in_data.size());
        
        // Header
        cipher.insert(cipher.end(), MAGIC, MAGIC + 4);
        cipher.push_back(VERSION); cipher.push_back(1); // 1 = AES
        cipher.push_back(SALT_SIZE); cipher.push_back(IV_SIZE);
        cipher.insert(cipher.end(), salt.begin(), salt.end());
        cipher.insert(cipher.end(), iv.begin(), iv.end());

        array<uint8_t, AES_BLOCK_SIZE> prev{};
        for (size_t i = 0; i < iv.size(); ++i) prev[i] = iv[i];

        for (size_t offset = 0; offset < in_data.size(); offset += AES_BLOCK_SIZE) {
            array<uint8_t, AES_BLOCK_SIZE> block{};
            for (size_t i = 0; i < AES_BLOCK_SIZE; ++i) block[i] = in_data[offset + i] ^ prev[i];
            block = encryptBlock(block, roundKeys);
            cipher.insert(cipher.end(), block.begin(), block.end());
            prev = block;
        }

        if (output.size < cipher.size()) return CryptoStatus::BufferTooSmall;
        memcpy(output.data, cipher.data(), cipher.size());
        return CryptoStatus::Success;
    }

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
        if (input.size < 40) return CryptoStatus::InvalidParam;
        if (input.data[0] != MAGIC[0] || input.data[1] != MAGIC[1] || input.data[2] != MAGIC[2] || input.data[3] != MAGIC[3]) return CryptoStatus::InvalidParam;

        vector<uint8_t> password(key.data, key.data + key.size);
        vector<uint8_t> salt(input.data + 8, input.data + 8 + SALT_SIZE);
        vector<uint8_t> iv(input.data + 8 + SALT_SIZE, input.data + 8 + SALT_SIZE + IV_SIZE);
        
        size_t data_offset = 8 + SALT_SIZE + IV_SIZE;
        vector<uint8_t> cipher_data(input.data + data_offset, input.data + input.size);

        if (cipher_data.size() % AES_BLOCK_SIZE != 0) return CryptoStatus::InvalidParam;

        vector<uint8_t> derived_key = deriveKey(password, salt, AES_KEY_SIZE);
        array<uint8_t, 176> roundKeys = expandKey(derived_key);

        vector<uint8_t> plain;
        plain.reserve(cipher_data.size());

        array<uint8_t, AES_BLOCK_SIZE> prev{};
        for (size_t i = 0; i < iv.size(); ++i) prev[i] = iv[i];

        for (size_t pos = 0; pos < cipher_data.size(); pos += AES_BLOCK_SIZE) {
            array<uint8_t, AES_BLOCK_SIZE> block{}, cipherBlock{};
            for (size_t i = 0; i < AES_BLOCK_SIZE; ++i) {
                block[i] = cipher_data[pos + i];
                cipherBlock[i] = cipher_data[pos + i];
            }
            block = decryptBlock(block, roundKeys);
            for (size_t i = 0; i < AES_BLOCK_SIZE; ++i) block[i] ^= prev[i];
            plain.insert(plain.end(), block.begin(), block.end());
            prev = cipherBlock;
        }

        uint8_t pad = plain.back();
        if (pad == 0 || pad > AES_BLOCK_SIZE || pad > plain.size()) return CryptoStatus::InvalidParam;
        plain.resize(plain.size() - pad); // Удаляем PKCS#7 паддинг

        if (output.size < plain.size()) return CryptoStatus::BufferTooSmall;
        
        // Записываем расшифрованные данные и зануляем остаток буфера (от паддинга)
        memcpy(output.data, plain.data(), plain.size());
        memset(output.data + plain.size(), 0, output.size - plain.size());
        
        return CryptoStatus::Success;
    }
}
