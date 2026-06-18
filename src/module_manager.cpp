#include "module_manager.h"
#include <stdexcept>

#ifdef _WIN32
    #define byte _windows_byte 
    #include <windows.h>
    #undef byte
#else
    #include <dlfcn.h>
#endif

using std::string;
using std::runtime_error;
using std::to_string;
using std::map;

ModuleManager::~ModuleManager() {
    unload_all();
}

bool ModuleManager::load_module(const string& path) {
    void* handle = nullptr;
    string error_msg = "";

#ifdef _WIN32
    handle = LoadLibraryA(path.c_str());
    if (!handle) error_msg = "Код ошибки Windows: " + to_string(GetLastError());
#else
    handle = dlopen(path.c_str(), RTLD_LAZY);
    if (!handle) error_msg = string(dlerror());
#endif

    if (!handle) throw runtime_error("Не удалось загрузить библиотеку " + path + ". " + error_msg);

    // Функция-помощник для кроссплатформенного dlsym
    auto get_sym = [handle](const char* sym_name) -> void* {
#ifdef _WIN32
        return reinterpret_cast<void*>(GetProcAddress(static_cast<HMODULE>(handle), sym_name));
#else
        return dlsym(handle, sym_name);
#endif
    };

    auto get_info = reinterpret_cast<get_info_t>(get_sym("get_algorithm_info"));
    auto get_size = reinterpret_cast<get_size_t>(get_sym("get_output_size"));
    auto encrypt_f = reinterpret_cast<crypt_t>(get_sym("encrypt"));
    auto decrypt_f = reinterpret_cast<crypt_t>(get_sym("decrypt"));
    auto gen_keys = reinterpret_cast<gen_keys_t>(get_sym("generate_keys"));

    if (!get_info || !get_size || !encrypt_f || !decrypt_f || !gen_keys) {
        throw runtime_error("Ошибка загрузки функций C ABI из: " + path);
    }

    LoadedModule mod;
    mod.handle = handle;
    mod.name = get_info()->algorithm_name;
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
#ifdef _WIN32
        FreeLibrary(static_cast<HMODULE>(mod.handle));
#else
        dlclose(mod.handle);
#endif
    }
    modules.clear();
}

LoadedModule* ModuleManager::get_module(const string& name) {
    if (modules.find(name) != modules.end()) return &modules[name];
    return nullptr;
}
