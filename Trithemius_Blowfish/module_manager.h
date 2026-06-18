#ifndef MODULE_MANAGER_H
#define MODULE_MANAGER_H

#include "encryption_interface.h"

#include <string>
#include <vector>

struct LoadedEncryptionModule {
    void* library_handle;
    IEncryptionModule* module_pointer;
    destroy_t destroy_function;
};

class ModuleManager {
private:
    std::vector<LoadedEncryptionModule> loaded_modules;

public:
    ModuleManager() = default;
    ModuleManager(const ModuleManager&) = delete;
    ModuleManager& operator=(const ModuleManager&) = delete;
    ~ModuleManager();

    bool load_module(const std::string& library_path);
    IEncryptionModule* get_module(const std::string& module_name) const;
    void unload_all();
};

#endif
