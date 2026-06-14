#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace crypto {

enum class Algorithm
{
    AES = 1,
    DES = 2
};

const char* algorithmToString(Algorithm algo);
bool parseAlgorithm(const std::string& text, Algorithm& algo);

void printStep(const std::string& text);
void printError(const std::string& text);

bool readBinaryFile(const std::string& path, std::vector<uint8_t>& data, std::string& error);
bool writeBinaryFile(const std::string& path, const std::vector<uint8_t>& data, std::string& error);

bool readTextFile(const std::string& path, std::string& data, std::string& error);
bool writeTextFile(const std::string& path, const std::string& data, std::string& error);

std::vector<uint8_t> makeRandomBytes(std::size_t count);
std::vector<uint8_t> deriveKey(const std::string& password,
                               const std::vector<uint8_t>& salt,
                               std::size_t keyLen);

void xorBuffer(uint8_t* left, const uint8_t* right, std::size_t len);

} // namespace crypto
