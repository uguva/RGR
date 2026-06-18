#include "encrypto.h"
#include "aes_cipher.h"
#include "des_cipher.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <cctype>

using namespace std;
namespace fs = std::filesystem;

namespace crypto {
namespace {

string bytesToHex(const vector<uint8_t>& data)
{
    static const char* digits = "0123456789ABCDEF";
    string result;
    result.reserve(data.size() * 2);

    for (uint8_t byte : data)
    {
        result.push_back(digits[(byte >> 4) & 0x0F]);
        result.push_back(digits[byte & 0x0F]);
    }

    return result;
}

int hexValue(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

bool hexToBytes(const string& text, vector<uint8_t>& data, string& error)
{
    string clean;
    clean.reserve(text.size());

    for (char c : text)
    {
        if (!isspace(static_cast<unsigned char>(c)))
            clean.push_back(c);
    }

    if (clean.size() % 2 != 0)
    {
        error = "HEX-строка должна содержать четное число символов.";
        return false;
    }

    data.clear();
    data.reserve(clean.size() / 2);

    for (size_t i = 0; i < clean.size(); i += 2)
    {
        int hi = hexValue(clean[i]);
        int lo = hexValue(clean[i + 1]);

        if (hi < 0 || lo < 0)
        {
            error = "В HEX-строке обнаружены недопустимые символы.";
            return false;
        }

        data.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }

    return true;
}

fs::path makeTempPath(const string& prefix, const string& suffix)
{
    auto bytes = makeRandomBytes(8);
    string token = bytesToHex(bytes);
    return fs::temp_directory_path() / (prefix + token + suffix);
}

bool saveBytesToTempFile(const vector<uint8_t>& data, fs::path& path, string& error)
{
    path = makeTempPath("crypto_", ".bin");
    if (!writeBinaryFile(path.u8string(), data, error))
        return false;
    return true;
}

bool loadBytesFromTempFile(const fs::path& path, vector<uint8_t>& data, string& error)
{
    return readBinaryFile(path.u8string(), data, error);
}

void removeTempFile(const fs::path& path)
{
    error_code ec;
    fs::remove(path, ec);
}

} // namespace

std::string generateKeyHex(Algorithm algorithm)
{
    const size_t keySize = (algorithm == Algorithm::AES) ? 16 : 8;
    return bytesToHex(makeRandomBytes(keySize));
}

bool encryptFile(Algorithm algorithm,
                 const string& inputPath,
                 const string& outputPath,
                 const string& keyText,
                 string& error)
{
    if (algorithm == Algorithm::AES)
        return aesEncryptFile(inputPath, outputPath, keyText, error);

    if (algorithm == Algorithm::DES)
        return desEncryptFile(inputPath, outputPath, keyText, error);

    error = "Неизвестный алгоритм.";
    return false;
}

bool decryptFile(Algorithm algorithm,
                 const string& inputPath,
                 const string& outputPath,
                 const string& keyText,
                 string& error)
{
    if (algorithm == Algorithm::AES)
        return aesDecryptFile(inputPath, outputPath, keyText, error);

    if (algorithm == Algorithm::DES)
        return desDecryptFile(inputPath, outputPath, keyText, error);

    error = "Неизвестный алгоритм.";
    return false;
}

bool encryptText(Algorithm algorithm,
                 const string& plainText,
                 const string& keyText,
                 string& cipherTextHex,
                 string& error)
{
    vector<uint8_t> bytes(plainText.begin(), plainText.end());

    fs::path inputTemp;
    fs::path outputTemp;

    if (!saveBytesToTempFile(bytes, inputTemp, error))
        return false;

    bool ok = false;
    if (algorithm == Algorithm::AES)
        ok = aesEncryptFile(inputTemp.u8string(), (outputTemp = makeTempPath("crypto_", ".enc")).u8string(), keyText, error);
    else if (algorithm == Algorithm::DES)
        ok = desEncryptFile(inputTemp.u8string(), (outputTemp = makeTempPath("crypto_", ".enc")).u8string(), keyText, error);
    else
        error = "Неизвестный алгоритм.";

    if (!ok)
    {
        removeTempFile(inputTemp);
        if (!outputTemp.empty()) removeTempFile(outputTemp);
        return false;
    }

    vector<uint8_t> cipherBytes;
    if (!loadBytesFromTempFile(outputTemp, cipherBytes, error))
    {
        removeTempFile(inputTemp);
        removeTempFile(outputTemp);
        return false;
    }

    cipherTextHex = bytesToHex(cipherBytes);

    removeTempFile(inputTemp);
    removeTempFile(outputTemp);
    return true;
}

bool decryptText(Algorithm algorithm,
                 const string& cipherTextHex,
                 const string& keyText,
                 string& plainText,
                 string& error)
{
    vector<uint8_t> cipherBytes;
    if (!hexToBytes(cipherTextHex, cipherBytes, error))
        return false;

    fs::path inputTemp;
    fs::path outputTemp;

    if (!saveBytesToTempFile(cipherBytes, inputTemp, error))
        return false;

    bool ok = false;
    if (algorithm == Algorithm::AES)
        ok = aesDecryptFile(inputTemp.u8string(), (outputTemp = makeTempPath("crypto_", ".txt")).u8string(), keyText, error);
    else if (algorithm == Algorithm::DES)
        ok = desDecryptFile(inputTemp.u8string(), (outputTemp = makeTempPath("crypto_", ".txt")).u8string(), keyText, error);
    else
        error = "Неизвестный алгоритм.";

    if (!ok)
    {
        removeTempFile(inputTemp);
        if (!outputTemp.empty()) removeTempFile(outputTemp);
        return false;
    }

    vector<uint8_t> plainBytes;
    if (!loadBytesFromTempFile(outputTemp, plainBytes, error))
    {
        removeTempFile(inputTemp);
        removeTempFile(outputTemp);
        return false;
    }

    plainText.assign(reinterpret_cast<const char*>(plainBytes.data()), plainBytes.size());

    removeTempFile(inputTemp);
    removeTempFile(outputTemp);
    return true;
}

} // namespace crypto
