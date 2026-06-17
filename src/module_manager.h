#ifndef MODULE_MANAGER_H
#define MODULE_MANAGER_H

#include "crypto_interface.h"
#include <string>
#include <map>

using namespace std;

typedef const AlgorithmInfo* (*get_info_t)();
typedef CryptoStatus (*get_size_t)(size_t, size_t*, bool);
typedef CryptoStatus (*crypt_t)(ConstBuffer, ConstBuffer, MutBuffer);
typedef CryptoStatus (*gen_keys_t)(const char*, char*, size_t, size_t*);

struct LoadedModule {
    void* handle;
    string name;
    get_info_t get_info;
    get_size_t get_size;
    crypt_t encrypt_func;
    crypt_t decrypt_func;
    gen_keys_t generate_keys;
};

class ModuleManager {
private:
    map<string, LoadedModule> modules;

public:
    ~ModuleManager();
    bool load_module(const string& path);
    void unload_all();
    LoadedModule* get_module(const string& name);
};

#endif
