#include "module_manager.h"
#include <dlfcn.h>
#include <stdexcept>

using namespace std;

ModuleManager::~ModuleManager() {
    unload_all();
}

bool ModuleManager::load_module(const string& path) {
    void* handle = dlopen(path.c_str(), RTLD_LAZY);
    if (!handle) {
        throw runtime_error("Не удалось загрузить библиотеку: " + string(dlerror()));
    }

    auto get_info = reinterpret_cast<get_info_t>(dlsym(handle, "get_algorithm_info"));
    auto get_size = reinterpret_cast<get_size_t>(dlsym(handle, "get_output_size"));
    auto encrypt_f = reinterpret_cast<crypt_t>(dlsym(handle, "encrypt"));
    auto decrypt_f = reinterpret_cast<crypt_t>(dlsym(handle, "decrypt"));
    auto gen_keys = reinterpret_cast<gen_keys_t>(dlsym(handle, "generate_keys"));

    if (!get_info || !get_size || !encrypt_f || !decrypt_f || !gen_keys) {
        dlclose(handle);
        throw runtime_error("Ошибка загрузки функций C ABI: " + string(dlerror()));
    }

    const AlgorithmInfo* info = get_info();
    
    LoadedModule mod;
    mod.handle = handle;
    mod.name = info->algorithm_name;
    mod.get_info = get_info;
    mod.get_size = get_size;
    mod.encrypt_func = encrypt_f;
    mod.decrypt_func = decrypt_f;
    mod.generate_keys = gen_keys;

    modules[mod.name] = mod;
    return true;
}

void ModuleManager::unload_all() {
    for (auto const& [name, mod] : modules) {
        dlclose(mod.handle);
    }
    modules.clear();
}

LoadedModule* ModuleManager::get_module(const string& name) {
    if (modules.find(name) != modules.end()) {
        return &modules[name];
    }
    return nullptr;
}
