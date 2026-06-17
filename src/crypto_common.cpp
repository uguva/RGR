#include "crypto_common.h"

#include <fstream>
#include <iostream>
#include <random>

using namespace std;

namespace crypto {

const char* algorithmToString(Algorithm algo)
{
    switch (algo)
    {
        case Algorithm::AES: return "AES";
        case Algorithm::DES: return "DES";
        default: return "Unknown";
    }
}

bool parseAlgorithm(const string& text, Algorithm& algo)
{
    if (text == "aes" || text == "AES")
    {
        algo = Algorithm::AES;
        return true;
    }

    if (text == "des" || text == "DES")
    {
        algo = Algorithm::DES;
        return true;
    }

    return false;
}

void printStep(const string& text)
{
    cout << "[*] " << text << endl;
}

void printError(const string& text)
{
    cerr << "[ERROR] " << text << endl;
}

bool readBinaryFile(const string& path, vector<uint8_t>& data, string& error)
{
    ifstream file(path, ios::binary);

    if (!file)
    {
        error = "Не удалось открыть входной файл. Проверьте путь и права доступа.";
        return false;
    }

    file.seekg(0, ios::end);
    streampos size = file.tellg();

    if (size < 0)
    {
        error = "Не удалось определить размер файла.";
        return false;
    }

    file.seekg(0, ios::beg);
    data.resize(static_cast<size_t>(size));

    if (!data.empty())
    {
        file.read(reinterpret_cast<char*>(data.data()), static_cast<streamsize>(data.size()));
        if (!file)
        {
            error = "Не удалось прочитать файл целиком.";
            return false;
        }
    }

    return true;
}

bool writeBinaryFile(const string& path, const vector<uint8_t>& data, string& error)
{
    ofstream file(path, ios::binary);

    if (!file)
    {
        error = "Не удалось создать выходной файл. Проверьте путь и права доступа.";
        return false;
    }

    if (!data.empty())
    {
        file.write(reinterpret_cast<const char*>(data.data()), static_cast<streamsize>(data.size()));
        if (!file)
        {
            error = "Не удалось записать данные в файл.";
            return false;
        }
    }

    return true;
}

bool readTextFile(const string& path, string& data, string& error)
{
    ifstream file(path, ios::binary);

    if (!file)
    {
        error = "Не удалось открыть текстовый файл.";
        return false;
    }

    file.seekg(0, ios::end);
    streampos size = file.tellg();

    if (size < 0)
    {
        error = "Не удалось определить размер текстового файла.";
        return false;
    }

    file.seekg(0, ios::beg);
    data.resize(static_cast<size_t>(size));

    if (!data.empty())
    {
        file.read(data.data(), static_cast<streamsize>(data.size()));
        if (!file)
        {
            error = "Не удалось прочитать текстовый файл.";
            return false;
        }
    }

    return true;
}

bool writeTextFile(const string& path, const string& data, string& error)
{
    ofstream file(path, ios::binary);

    if (!file)
    {
        error = "Не удалось создать текстовый файл.";
        return false;
    }

    file.write(data.data(), static_cast<streamsize>(data.size()));
    if (!file)
    {
        error = "Не удалось записать текстовый файл.";
        return false;
    }

    return true;
}

vector<uint8_t> makeRandomBytes(size_t count)
{
    vector<uint8_t> result(count);

    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<int> dist(0, 255);

    for (size_t i = 0; i < count; ++i)
    {
        result[i] = static_cast<uint8_t>(dist(gen));
    }

    return result;
}

vector<uint8_t> deriveKey(const string& password,
                          const vector<uint8_t>& salt,
                          size_t keyLen)
{
    vector<uint8_t> key(keyLen, 0);

    if (password.empty())
    {
        return key;
    }

    for (size_t i = 0; i < keyLen; ++i)
    {
        uint8_t p = static_cast<uint8_t>(password[i % password.size()]);
        uint8_t s = salt.empty() ? 0 : salt[i % salt.size()];
        key[i] = static_cast<uint8_t>((p ^ s ^ static_cast<uint8_t>(i * 17 + 31)) + static_cast<uint8_t>(i * 13));
    }

    for (int round = 0; round < 1024; ++round)
    {
        for (size_t i = 0; i < keyLen; ++i)
        {
            uint8_t p = static_cast<uint8_t>(password[(i + round) % password.size()]);
            uint8_t s = salt.empty() ? 0 : salt[(i + round) % salt.size()];
            uint8_t x = static_cast<uint8_t>(key[i] ^ p ^ s ^ static_cast<uint8_t>(round + i));

            key[i] = static_cast<uint8_t>((x << ((i + round) & 7)) | (x >> (8 - ((i + round) & 7))));
        }
    }

    return key;
}

void xorBuffer(uint8_t* left, const uint8_t* right, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        left[i] ^= right[i];
    }
}

} // namespace crypto
