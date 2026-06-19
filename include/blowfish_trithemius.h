#ifndef BLOWFISH_TRITHEMIUS_H
#define BLOWFISH_TRITHEMIUS_H

#include <cstdint>
#include <string>
#include <vector>

class IEncryptionModule {
public:
    virtual ~IEncryptionModule() = default;

    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t>& input_data,
                                         const std::string& key_text) = 0;

    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t>& encrypted_data,
                                         const std::string& key_text) = 0;

    virtual std::string get_name() const = 0;
    virtual std::string get_extension() const = 0;
};

using create_t = IEncryptionModule* (*)();
using destroy_t = void (*)(IEncryptionModule*);

#endif
