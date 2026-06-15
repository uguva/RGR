#ifndef ENCRYPTION_INTERFACE_H
#define ENCRYPTION_INTERFACE_H

#include <string>
#include <vector>
#include <cstdint>

using namespace std;

class IEncryptionModule {
public:
    virtual ~IEncryptionModule() {}
    virtual vector<uint8_t> encrypt(const vector<uint8_t>& payload, const string& password) = 0;
    virtual vector<uint8_t> decrypt(const vector<uint8_t>& cipher, const string& password) = 0;
    virtual string get_extension() const = 0;
    virtual string get_name() const = 0;
};

typedef IEncryptionModule* (*create_t)();
typedef void (*destroy_t)(IEncryptionModule*);

extern "C" IEncryptionModule* create_module();
extern "C" void destroy_module(IEncryptionModule* module);

#endif
