#ifndef MODULE_MANAGER_H
#define MODULE_MANAGER_H

#include "crypto_interface.h"
#include <string>
#include <map>
#include <utility>

#ifdef _WIN32
    #define byte _windows_byte 
    #include <windows.h>
    #undef byte
#else
    #include <dlfcn.h>
#endif


typedef const AlgorithmInfo* (*get_info_t)();
typedef CryptoStatus (*get_size_t)(size_t, size_t*, bool);
typedef CryptoStatus (*crypt_t)(ConstBuffer, ConstBuffer, MutBuffer);
typedef CryptoStatus (*gen_keys_t)(const char*, char*, size_t, size_t*);

struct LoadedModule {
    void* handle = nullptr;
    std::string name;
    get_info_t get_info = nullptr;
    get_size_t get_size = nullptr;
    crypt_t encrypt_func = nullptr;
    crypt_t decrypt_func = nullptr;
    gen_keys_t generate_keys = nullptr;

    // Конструкторы по умолчанию
    LoadedModule() = default;

    // Запрет копирования
    LoadedModule(const LoadedModule&) = delete;
    LoadedModule& operator=(const LoadedModule&) = delete;

    // Безопасная передача владения в std::map
    LoadedModule(LoadedModule&& other) noexcept 
        : handle(other.handle), 
          name(std::move(other.name)), 
          get_info(other.get_info), 
          get_size(other.get_size), 
          encrypt_func(other.encrypt_func), 
          decrypt_func(other.decrypt_func), 
          generate_keys(other.generate_keys) 
    {
        other.handle = nullptr; // Обнуляем дескриптор у старого объекта
    }

    LoadedModule& operator=(LoadedModule&& other) noexcept {
        if (this != &other) {
            unload(); // Выгружаем текущую библиотеку, если она была загружена
            handle = other.handle;
            name = std::move(other.name);
            get_info = other.get_info;
            get_size = other.get_size;
            encrypt_func = other.encrypt_func;
            decrypt_func = other.decrypt_func;
            generate_keys = other.generate_keys;
            other.handle = nullptr;
        }
        return *this;
    }

    // Деструктор автоматически и безопасно освобождает библиотеку
    ~LoadedModule() {
        unload();
    }

private:
    void unload() {
        if (handle) {
#ifdef _WIN32
            FreeLibrary(static_cast<HMODULE>(handle));
#else
            dlclose(handle);
#endif
            handle = nullptr;
        }
    }
};

class ModuleManager {
private:
    std::map<std::string, LoadedModule> modules;

public:
    ModuleManager() = default;
    ~ModuleManager();
    
    // Запрещаем копирование менеджера
    ModuleManager(const ModuleManager&) = delete;
    ModuleManager& operator=(const ModuleManager&) = delete;

    bool load_module(const std::string& path);
    void unload_all();
    LoadedModule* get_module(const std::string& name);
};

#endif // MODULE_MANAGER_H
