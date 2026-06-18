#ifndef UI_UTILS_H
#define UI_UTILS_H

#include <iostream>
#include <vector>
#include <string>
#include <limits>
#include <exception>
#include "module_manager.h"

// Пользовательское исключение для безопасной отмены операций и возврата в меню
struct CancelOperation : public std::exception {
    const char* what() const noexcept override {
        return "Операция отменена пользователем.";
    }
};

// Шаблонная функция для безопасного выбора пунктов меню (с защитой от неверного ввода)
template <typename T>
T get_choice(T min, T max) {
    T choice;
    while (true) {
        if (std::cin >> choice && choice >= min && choice <= max) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            return choice;
        }
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cout << "Неверный ввод. Попробуйте снова: ";
    }
}

// Прототипы UI функций
void clear_input();
bool login();
std::vector<uint8_t> get_input_data(bool is_encrypt, std::string& created_file_path);
std::vector<uint8_t> get_key_data(const std::string& algo_name, bool is_encrypt);
void save_output_data(const std::vector<uint8_t>& data, bool is_encrypt);
void process_crypto(LoadedModule* mod, bool is_encrypt);
void process_keygen(LoadedModule* mod);

#endif
