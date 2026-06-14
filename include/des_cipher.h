#pragma once

#include <string>

namespace crypto {

bool desEncryptFile(const std::string& inputPath,
                    const std::string& outputPath,
                    const std::string& password,
                    std::string& error);

bool desDecryptFile(const std::string& inputPath,
                    const std::string& outputPath,
                    const std::string& password,
                    std::string& error);

} // namespace crypto
