#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include "module_manager.h"
#include "ui_utils.h"

using std::cin;
using std::cout;
using std::endl;
using std::string;
using std::exception;

// Перечисления для навигации главного меню
enum class MenuOption { Exit = 0, RSA = 1, DiffieHellman = 2, AES = 3, DES = 4, Affine = 5, Vernam = 6 };

// Включение Windows.h с защитой от конфликта типов byte
#ifdef _WIN32
    #define byte _windows_byte
    #include <windows.h>
    #undef byte
#endif

int main() {
#ifdef _WIN32
    // Настройка локализации UTF-8 для Windows
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    if (!login()) {
        cout << "Ошибка доступа." << endl;
        return 1;
    }

    ModuleManager manager;
    try {
        // Кроссплатформенная загрузка библиотек плагинов
        #ifdef _WIN32
            manager.load_module("./plugins/rsa/librsa.dll");
            manager.load_module("./plugins/DiffieHellman/libdh.dll");
            manager.load_module("./plugins/aes/libaes.dll");
            manager.load_module("./plugins/des/libdes.dll");
            manager.load_module("./plugins/affine/libaffine.dll");
            manager.load_module("./plugins/vernam/libvernam.dll");
        #else
            manager.load_module("./plugins/rsa/librsa.so");
            manager.load_module("./plugins/DiffieHellman/libdh.so");
            manager.load_module("./plugins/aes/libaes.so");
            manager.load_module("./plugins/des/libdes.so");
            manager.load_module("./plugins/affine/libaffine.so");
            manager.load_module("./plugins/vernam/libvernam.so");
        #endif
    } catch (const exception& e) {
        std::cerr << "\n[ВНИМАНИЕ]: " << e.what() << "\n" << endl;
    }

    while (true) {
        cout << "\n=== ГЛАВНОЕ МЕНЮ ===" << endl;
        cout << "1. Протокол RSA\n2. Протокол Diffie-Hellman\n3. Протокол AES\n4. Протокол DES\n5. Аффинный шифр\n6. Шифр Вернама\n0. Выход из программы" << endl;
        cout << "Выберите операцию: ";
        
        MenuOption choice = static_cast<MenuOption>(get_choice<int>(0, 6));

        switch (choice) {
            case MenuOption::RSA:           run_sub_menu(manager.get_module("RSA"), "RSA"); break;
            case MenuOption::DiffieHellman: run_sub_menu(manager.get_module("DiffieHellman"), "Diffie-Hellman"); break;
            case MenuOption::AES:           run_sub_menu(manager.get_module("AES"), "AES"); break;
            case MenuOption::DES:           run_sub_menu(manager.get_module("DES"), "DES"); break;
            case MenuOption::Affine:        run_sub_menu(manager.get_module("Affine"), "Аффинный шифр"); break;
            case MenuOption::Vernam:        run_sub_menu(manager.get_module("Vernam"), "Шифр Вернама"); break;
            case MenuOption::Exit:          cout << "Завершение работы..." << endl; return 0;
        }
    }
    return 0;
}
