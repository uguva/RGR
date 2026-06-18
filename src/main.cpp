#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <limits>
#include <cstdio>
#include "module_manager.h"
#include "ui_utils.h"

#ifdef _WIN32
    #define byte _windows_byte
    #include <windows.h>
    #undef byte
#endif

using std::cin;
using std::cout;
using std::endl;
using std::string;
using std::vector;
using std::ifstream;
using std::ofstream;
using std::ios;
using std::getline;
using std::exception;
using std::runtime_error;
using std::streamsize;
using std::numeric_limits;

// Перечисления для навигации меню (enum class)
enum class MenuOption { Exit = 0, RSA = 1, DiffieHellman = 2 };
enum class SubMenuOption { Back = 0, Keygen = 1, Encrypt = 2, Decrypt = 3 };

int main() {

    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #endif

    if (!login()) {
        cout << "Ошибка доступа." << endl;
        return 1;
    }

    ModuleManager manager;
    try {
        #ifdef _WIN32
            manager.load_module("./plugins/rsa/librsa.dll");
            manager.load_module("./plugins/DiffieHellman/libdh.dll");
        #else
            manager.load_module("./plugins/rsa/librsa.so");
            manager.load_module("./plugins/DiffieHellman/libdh.so");
        #endif
    } catch (const exception& e) {
        cerr << "\n[ВНИМАНИЕ]: " << e.what() << "\n" << endl;
    }

    while (true) {
        cout << "\n=== ГЛАВНОЕ МЕНЮ ===" << endl;
        cout << "1. Протокол RSA" << endl;
        cout << "2. Протокол Diffie-Hellman" << endl;
        cout << "0. Выход из программы" << endl;
        cout << "Выберите операцию: ";
        
        MenuOption choice = static_cast<MenuOption>(get_choice<int>(0, 2));

        switch (choice) {
            case MenuOption::RSA:
                // Локальная функция подменю, использующая switch-case
                {
                    auto mod = manager.get_module("RSA");
                    if (!mod) { cerr << "[ОШИБКА]: RSA модуль не загружен" << endl; break; }
                    while (true) {
                        cout << "\n--- Меню: RSA ---\n1. Ключи\n2. Шифр\n3. Расшифр\n0. Назад\nВыбор: ";
                        SubMenuOption sub = static_cast<SubMenuOption>(get_choice<int>(0, 3));
                        switch (sub) {
                            case SubMenuOption::Keygen: process_keygen(mod); break;
                            case SubMenuOption::Encrypt: process_crypto(mod, true); break;
                            case SubMenuOption::Decrypt: process_crypto(mod, false); break;
                            case SubMenuOption::Back: goto end_rsa;
                        }
                    }
                    end_rsa:;
                }
                break;

            case MenuOption::DiffieHellman:
                {
                    auto mod = manager.get_module("DiffieHellman");
                    if (!mod) { cerr << "[ОШИБКА]: DH модуль не загружен" << endl; break; }
                    while (true) {
                        cout << "\n--- Меню: Diffie-Hellman ---\n1. Ключи\n2. Шифр\n3. Расшифр\n0. Назад\nВыбор: ";
                        SubMenuOption sub = static_cast<SubMenuOption>(get_choice<int>(0, 3));
                        switch (sub) {
                            case SubMenuOption::Keygen: process_keygen(mod); break;
                            case SubMenuOption::Encrypt: process_crypto(mod, true); break;
                            case SubMenuOption::Decrypt: process_crypto(mod, false); break;
                            case SubMenuOption::Back: goto end_dh;
                        }
                    }
                    end_dh:;
                }
                break;

            case MenuOption::Exit:
                return 0;
        }
    }
    return 0;
}
