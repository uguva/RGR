#pragma once

#include <string>

namespace crypto {

bool aesEncryptFile(const std::string& inputPath,
                    const std::string& outputPath,
                    const std::string& password,
                    std::string& error);

bool aesDecryptFile(const std::string& inputPath,
                    const std::string& outputPath,
                    const std::string& password,
                    std::string& error);

} // namespace crypto
