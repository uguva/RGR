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

// map вызовет деструкторы LoadedModule
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

    if (!handle) {
        throw runtime_error("Не удалось загрузить библиотеку " + path + ". " + error_msg);
    }

    // лямбда-помощник получения адреса символа
    auto get_sym = [handle](const char* sym_name) -> void* {
#ifdef _WIN32
        return reinterpret_cast<void*>(GetProcAddress(static_cast<HMODULE>(handle), sym_name));
#else
        return dlsym(handle, sym_name);
#endif
    };

    get_info_t get_info = reinterpret_cast<get_info_t>(get_sym("get_algorithm_info"));
    get_size_t get_size = reinterpret_cast<get_size_t>(get_sym("get_output_size"));
    crypt_t encrypt_f = reinterpret_cast<crypt_t>(get_sym("encrypt"));
    crypt_t decrypt_f = reinterpret_cast<crypt_t>(get_sym("decrypt"));
    gen_keys_t gen_keys = reinterpret_cast<gen_keys_t>(get_sym("generate_keys"));

    // Если функции ABI не найдены, освобождаем handle до генерации throw
    if (!get_info || !get_size || !encrypt_f || !decrypt_f || !gen_keys) {
#ifdef _WIN32
        FreeLibrary(static_cast<HMODULE>(handle));
#else
        dlclose(handle);
#endif
        throw runtime_error("Ошибка загрузки функций C ABI из: " + path);
    }

    // Безопасный вызов get_info() плагина с перехватом системных исключений
    string module_name;
    try {
        const AlgorithmInfo* info = get_info();
        if (!info || !info->algorithm_name) { 
            throw runtime_error("Плагин вернул некорректную структуру AlgorithmInfo.");
        }
        module_name = info->algorithm_name; 
    } catch (...) {
#ifdef _WIN32
        FreeLibrary(static_cast<HMODULE>(handle));
#else
        dlclose(handle);
#endif
        throw runtime_error("Критический сбой (Crash) при чтении метаданных get_algorithm_info из: " + path);
    }

    // объект модуля
    LoadedModule mod;
    mod.handle = handle;
    mod.name = module_name;
    mod.get_info = get_info;
    mod.get_size = get_size;
    mod.encrypt_func = encrypt_f;
    mod.decrypt_func = decrypt_f;
    mod.generate_keys = gen_keys;

    // Перемещение (std::move) вместо копирования
    // Старый временный дескриптор в 'mod' занулится и не выгрузит DLL досрочно
    modules[mod.name] = std::move(mod);
    
    return true;
}

void ModuleManager::unload_all() {
    // Очистка мапы вызовет деструкторы у всех LoadedModule
    modules.clear();
}

LoadedModule* ModuleManager::get_module(const string& name) {
    auto it = modules.find(name);
    if (it != modules.end()) {
        return &(it->second);
    }
    return nullptr;
}
