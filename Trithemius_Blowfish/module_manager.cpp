#include "module_manager.h"

#include <dlfcn.h>
#include <iostream>

using namespace std;

ModuleManager::~ModuleManager() {
    unload_all();
}

bool ModuleManager::load_module(const string& library_path) {
    void* library_handle = dlopen(library_path.c_str(), RTLD_LAZY);

    if (library_handle == nullptr) {
        cout << "Ошибка загрузки библиотеки: " << library_path << endl;
        cout << dlerror() << endl;
        return false;
    }

    dlerror();

    create_t create_function = reinterpret_cast<create_t>(dlsym(library_handle, "create"));
    const char* create_error = dlerror();

    destroy_t destroy_function = reinterpret_cast<destroy_t>(dlsym(library_handle, "destroy"));
    const char* destroy_error = dlerror();

    if (create_error != nullptr || destroy_error != nullptr || create_function == nullptr || destroy_function == nullptr) {
        cout << "Ошибка получения функций create/destroy из библиотеки: " << library_path << endl;
        dlclose(library_handle);
        return false;
    }

    IEncryptionModule* module_pointer = create_function();

    loaded_modules.push_back({library_handle, module_pointer, destroy_function});
    return true;
}

IEncryptionModule* ModuleManager::get_module(const string& module_name) const {
    for (const LoadedEncryptionModule& loaded_module : loaded_modules) {
        if (loaded_module.module_pointer != nullptr && loaded_module.module_pointer->get_name() == module_name) {
            return loaded_module.module_pointer;
        }
    }

    return nullptr;
}

void ModuleManager::unload_all() {
    for (LoadedEncryptionModule& loaded_module : loaded_modules) {
        if (loaded_module.module_pointer != nullptr && loaded_module.destroy_function != nullptr) {
            loaded_module.destroy_function(loaded_module.module_pointer);
            loaded_module.module_pointer = nullptr;
        }

        if (loaded_module.library_handle != nullptr) {
            dlclose(loaded_module.library_handle);
            loaded_module.library_handle = nullptr;
        }
    }

    loaded_modules.clear();
}
