#pragma once

#include "crypto_common.h"

#include <string>

namespace crypto {

// Унифицированный интерфейс для всех подключаемых алгоритмов
bool encryptFile(Algorithm algorithm,
                 const std::string& inputPath,
                 const std::string& outputPath,
                 const std::string& keyText,
                 std::string& error);

bool decryptFile(Algorithm algorithm,
                 const std::string& inputPath,
                 const std::string& outputPath,
                 const std::string& keyText,
                 std::string& error);

// Обработка текстовых данных через тот же криптографический модуль
bool encryptText(Algorithm algorithm,
                 const std::string& plainText,
                 const std::string& keyText,
                 std::string& cipherTextHex,
                 std::string& error);

bool decryptText(Algorithm algorithm,
                 const std::string& cipherTextHex,
                 const std::string& keyText,
                 std::string& plainText,
                 std::string& error);

// Генератор ключей в виде HEX-строки
std::string generateKeyHex(Algorithm algorithm);

} // namespace crypto
