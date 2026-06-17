#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <limits>
#include <cstdio>
#include "module_manager.h"

using namespace std;

// Пользовательское исключение для безопасной отмены операций и возврата в меню
struct CancelOperation : public exception {
    const char* what() const noexcept override {
        return "Операция отменена пользователем.";
    }
};

void clear_input() {
    cin.clear();
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
}

bool login() {
    string password;
    cout << "Введите пароль для доступа к системе: ";
    cin >> password;
    return (password == "admin123");
}


vector<uint8_t> get_input_data(bool is_encrypt, string& created_file_path) {
    int choice;
    created_file_path.clear(); // Изначально файл не создан

    while (true) {
        if (is_encrypt) {
            cout << "\nОткуда взять данные для шифрования?\n1. Прочитать из существующего файла\n2. Ввести текст в консоль\n3. Создать новый файл и записать в него\n0. Назад (в меню)\nВыбор: ";
        } else {
            cout << "\nОткуда взять зашифрованные данные?\n1. Прочитать из существующего файла\n0. Назад (в меню)\nВыбор: ";
        }

        if (cin >> choice) {
            if (choice == 0) throw CancelOperation();
            if (is_encrypt && choice >= 1 && choice <= 3) { clear_input(); break; }
            if (!is_encrypt && choice == 1) { clear_input(); break; }
        }
        clear_input();
        cout << "Неверный ввод. Попробуйте снова." << endl;
    }

    if (choice == 1) {
        cout << "Введите путь к существующему файлу (или 0 для отмены): ";
        string path;
        getline(cin, path);
        if (path == "0") throw CancelOperation();
        
        ifstream file(path, ios::binary);
        if (!file.is_open()) throw runtime_error("Не удалось открыть входной файл. Проверьте права и путь.");
        return vector<uint8_t>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    } else if (choice == 2) {
        cout << "Введите текст (или 0 для отмены): ";
        string text;
        getline(cin, text);
        if (text == "0") throw CancelOperation();
        return vector<uint8_t>(text.begin(), text.end());
    } else {
        cout << "Введите путь для нового файла (или 0 для отмены): ";
        string path;
        getline(cin, path);
        if (path == "0") throw CancelOperation();
        
        cout << "Введите текст для записи в файл: ";
        string text;
        getline(cin, text);
        
        ofstream file(path, ios::binary);
        if (!file.is_open()) throw runtime_error("Не удалось создать файл.");
        file << text;
        file.close();

        created_file_path = path; // Запоминаем путь к созданному файлу для отслеживания
        return vector<uint8_t>(text.begin(), text.end());
    }
}

vector<uint8_t> get_key_data(const string& algo_name, bool is_encrypt) {
    int choice;
    while (true) {
        cout << "\nКак ввести ключ?\n1. Загрузить из файла\n2. Ввести текстом в консоль\n0. Назад (в меню)\nВыбор: ";
        if (cin >> choice && choice >= 0 && choice <= 2) {
            clear_input();
            break;
        }
        clear_input();
        cout << "Неверный ввод." << endl;
    }

    if (choice == 0) throw CancelOperation();

    if (choice == 1) {
        cout << "Введите путь к файлу ключа (или 0 для отмены): ";
        string path;
        getline(cin, path);
        if (path == "0") throw CancelOperation();
        
        ifstream file(path, ios::binary);
        if (!file.is_open()) throw runtime_error("Не удалось открыть файл ключа.");
        return vector<uint8_t>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    } else {
        if (algo_name == "RSA") {
            if (is_encrypt) cout << "Введите ключ (формат 'Public: e,n' или 'e,n') [или 0 для отмены]: ";
            else cout << "Введите ключ (формат 'Private: d,n' или 'd,n') [или 0 для отмены]: ";
        } else if (algo_name == "DiffieHellman") {
            cout << "Введите ключ (формат 'p g priv pub_enemy') [или 0 для отмены]: ";
        } else {
            cout << "Введите ключ [или 0 для отмены]: ";
        }
        string text;
        getline(cin, text);
        if (text == "0") throw CancelOperation();
        return vector<uint8_t>(text.begin(), text.end());
    }
}

void save_output_data(const vector<uint8_t>& data, bool is_encrypt) {
    int choice = 1;
    if (!is_encrypt) {
        while (true) {
            cout << "\nКуда сохранить расшифрованный результат?\n1. В файл\n2. Вывести в консоль\n0. Назад (в меню)\nВыбор: ";
            if (cin >> choice && choice >= 0 && choice <= 2) {
                clear_input();
                break;
            }
            clear_input();
            cout << "Неверный ввод." << endl;
        }
        if (choice == 0) throw CancelOperation();
    } else {
        cout << "\n[Зашифрованные данные сохраняются строго в двоичный файл]\n";
    }

    if (choice == 1 || is_encrypt) {
        cout << "Введите путь для сохранения файла (или 0 для отмены): ";
        string path;
        getline(cin, path);
        if (path == "0") throw CancelOperation();
        
        if (is_encrypt) {
            if (path.length() < 4 || path.substr(path.length() - 4) != ".bin") {
                path += ".bin";
            }
        }

        ofstream file(path, ios::binary);
        if (!file.is_open()) throw runtime_error("Не удалось создать файл для записи.");
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        cout << ">>> Успешно! Файл сохранен: " << path << endl;
    } else {
        cout << "\n>>> Результат:\n" << string(data.begin(), data.end()) << "\n" << endl;
    }
}

void process_crypto(LoadedModule* mod, bool is_encrypt) {
    string temp_file_path = ""; // Сюда запишется путь к созданному файлу
    try {
        vector<uint8_t> in_data = get_input_data(is_encrypt, temp_file_path);
        if (in_data.empty()) throw runtime_error("Входные данные пусты.");

        vector<uint8_t> key_data = get_key_data(mod->name, is_encrypt);
        if (key_data.empty()) throw runtime_error("Ключ не может быть пустым.");

        size_t out_size = 0;
        if (mod->get_size(in_data.size(), &out_size, is_encrypt) != CryptoStatus::Success) {
            throw runtime_error("Ошибка вычисления размера буфера.");
        }

        vector<uint8_t> out_data(out_size);
        ConstBuffer src = {in_data.data(), in_data.size()};
        ConstBuffer key = {key_data.data(), key_data.size()};
        MutBuffer dst = {out_data.data(), out_data.size()};

        CryptoStatus status = is_encrypt ? mod->encrypt_func(src, key, dst) : mod->decrypt_func(src, key, dst);

        if (status == CryptoStatus::Success) {
            save_output_data(out_data, is_encrypt); 
        } else if (status == CryptoStatus::InvalidParam) {
            throw runtime_error("Неверный формат ключа или параметров.");
        } else {
            throw runtime_error("Криптографическая операция завершилась ошибкой.");
        }

        secure_memory_clear(key_data);
        secure_memory_clear(in_data);
        secure_memory_clear(out_data);

    } catch (const CancelOperation& e) {
        cout << "\n[" << e.what() << " Возврат в меню...]\n" << endl;
        
        // УЧАСТОК МОДИФИКАЦИИ: Если временный файл был создан — удаляем его из системы
        if (!temp_file_path.empty()) {
            std::remove(temp_file_path.c_str());
            cout << "[СИСТЕМА]: Временный файл " << temp_file_path << " был автоматически удален." << endl;
        }
    } catch (const exception& e) {
        cerr << "\n[ОШИБКА]: " << e.what() << "\n" << endl;
        
        // Если произошла любая другая непредвиденная ошибка исходный пустой/битый файл тоже чистим
        if (!temp_file_path.empty()) {
            std::remove(temp_file_path.c_str());
        }
    }
}

void process_keygen(LoadedModule* mod) {
    try {
        string params;
        if (mod->name == "RSA") {
            cout << "Введите два простых числа через пробел (p q) [или 0 для отмены]: ";
        } else if (mod->name == "DiffieHellman") {
            cout << "Введите генератор, простое число и секретный ключ (g p a) [или 0 для отмены]: ";
        } else {
            cout << "Введите параметры генерации [или 0 для отмены]: ";
        }
        
        getline(cin, params);
        if (params == "0") throw CancelOperation();
        
        char buffer[1024] = {0};
        size_t written = 0;
        
        CryptoStatus status = mod->generate_keys(params.c_str(), buffer, sizeof(buffer), &written);
        if (status == CryptoStatus::Success) {
            cout << "\n>>> Ключи успешно сгенерированы!\n";
            
            int save_choice;
            while (true) {
                cout << "\nКак поступить с ключами?\n1. Вывести в консоль\n2. Сохранить в файл\n0. Отменить сохранение и выйти\nВыбор: ";
                if (cin >> save_choice && save_choice >= 0 && save_choice <= 2) {
                    clear_input();
                    break;
                }
                clear_input();
                cout << "Неверный ввод.\n";
            }

            if (save_choice == 0) throw CancelOperation();
            
            vector<uint8_t> key_data(buffer, buffer + written);

            if (save_choice == 1) {
                cout << "\n>>> Ваши ключи:\n" << buffer << endl;
            } else if (save_choice == 2) {
                cout << "Введите путь для сохранения ключей (или 0 для отмены): ";
                string path;
                getline(cin, path);
                if (path == "0") throw CancelOperation();
                
                ofstream file(path, ios::binary);
                if (file.is_open()) {
                    file.write(reinterpret_cast<const char*>(key_data.data()), key_data.size());
                    cout << ">>> Ключи сохранены в " << path << endl;
                } else {
                    throw runtime_error("Не удалось сохранить ключи по указанному пути.");
                }
            }

        } else if (status == CryptoStatus::InvalidParam) {
            throw runtime_error("Неверные параметры. Проверьте правильность чисел и формат ввода.");
        } else {
            throw runtime_error("Ошибка генерации ключей.");
        }
    } catch (const CancelOperation& e) {
        cout << "\n[" << e.what() << " Возврат в меню...]\n" << endl;
    } catch (const exception& e) {
        cerr << "\n[ОШИБКА]: " << e.what() << "\n" << endl;
    }
}

void sub_menu(LoadedModule* mod) {
    if (!mod) {
        cerr << "[ОШИБКА]: Модуль не загружен!" << endl;
        return;
    }

    int choice = -1;
    while (true) {
        cout << "\n--- Меню: " << mod->name << " ---" << endl;
        cout << "1. Сгенерировать ключи" << endl;
        cout << "2. Зашифровать данные" << endl;
        cout << "3. Расшифровать данные" << endl;
        cout << "0. Назад (В Главное меню)" << endl;
        cout << "Выбор: ";
        if (!(cin >> choice)) {
            clear_input();
            continue;
        }
        clear_input();

        if (choice == 1) process_keygen(mod);
        else if (choice == 2) process_crypto(mod, true);
        else if (choice == 3) process_crypto(mod, false);
        else if (choice == 0) break;
    }
}

int main() {
    if (!login()) {
        cout << "Ошибка доступа." << endl;
        return 1;
    }

    ModuleManager manager;
    try {
        manager.load_module("./plugins/rsa/librsa.so");
        manager.load_module("./plugins/DiffieHellman/libdh.so");
    } catch (const exception& e) {
        cerr << "\n[ВНИМАНИЕ]: " << e.what() << "\n" << endl;
    }

    int choice = -1;
    while (true) {
        cout << "\n=== ГЛАВНОЕ МЕНЮ ===" << endl;
        cout << "1. Протокол RSA" << endl;
        cout << "2. Протокол Diffie-Hellman" << endl;
        cout << "0. Выход из программы" << endl;
        cout << "Выберите операцию: ";
        if (!(cin >> choice)) {
            clear_input();
            continue;
        }
        clear_input();

        if (choice == 1) sub_menu(manager.get_module("RSA"));
        else if (choice == 2) sub_menu(manager.get_module("DiffieHellman"));
        else if (choice == 0) break;
    }
    return 0;
}
