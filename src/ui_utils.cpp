#include "ui_utils.h"
#include <iostream>
#include <fstream>
#include <cstdio>
#include <limits>
#include <stdexcept>

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
    created_file_path.clear();

    while (true) {
        if (is_encrypt) {
            cout << "\nОткуда взять данные для шифрования?\n"
                 << "1. Прочитать из существующего файла\n"
                 << "2. Ввести текст в консоль\n"
                 << "3. Создать новый файл и записать в него\n"
                 << "0. Назад (в меню)\nВыбор: ";
        } else {
            cout << "\nОткуда взять зашифрованные данные?\n"
                 << "1. Прочитать из существующего файла\n"
                 << "0. Назад (в меню)\nВыбор: ";
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
        if (!file.is_open()) throw runtime_error("Не удалось открыть входной файл. Проверьте путь и права.");
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

        created_file_path = path; // Запоминаем для удаления в случае отмены на следующих шагах
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
            if (is_encrypt) cout << "Введите ключ (формат 'Public: e,n' или просто 'e,n') [или 0 для отмены]: ";
            else cout << "Введите ключ (формат 'Private: d,n' или просто 'd,n') [или 0 для отмены]: ";
        } else if (algo_name == "DiffieHellman") {
            cout << "Введите ключ (формат 'p g priv pub_enemy' через пробел) [или 0 для отмены]: ";
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
        // Открываем файл строго в бинарном режиме ios::binary
        ofstream file(path, ios::binary);
        if (!file.is_open()) throw runtime_error("Не удалось создать файл для записи.");

        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        file.close(); // Явно закрываем поток
        
        cout << ">>> Успешно! Двоичный файл сохранен: " << path << endl;
    } else {
        cout << "\n>>> Результат:\n" << string(data.begin(), data.end()) << "\n" << endl;
    }
}

void process_crypto(LoadedModule* mod, bool is_encrypt) {
    string temp_file_path = "";
    try {
        vector<uint8_t> in_data = get_input_data(is_encrypt, temp_file_path);
        if (in_data.empty()) throw runtime_error("Входные данные пусты.");

        vector<uint8_t> key_data = get_key_data(mod->name, is_encrypt);
        if (key_data.empty()) throw runtime_error("Ключ пуст.");

        size_t out_size = 0;
        if (mod->get_size(in_data.size(), &out_size, is_encrypt) != CryptoStatus::Success) {
            throw runtime_error("Ошибка вычисления размера выходного буфера.");
        }

        vector<uint8_t> out_data(out_size);
        ConstBuffer src = {in_data.data(), in_data.size()};
        ConstBuffer key = {key_data.data(), key_data.size()};
        MutBuffer dst = {out_data.data(), out_data.size()};

        CryptoStatus status = is_encrypt ? mod->encrypt_func(src, key, dst) : mod->decrypt_func(src, key, dst);

        if (status == CryptoStatus::Success) {
            save_output_data(out_data, is_encrypt); 
        } else if (status == CryptoStatus::InvalidParam) {
            throw runtime_error("Неверный формат ключа или параметров шифра.");
        } else {
            throw runtime_error("Криптографическая операция завершилась ошибкой.");
        }

        // Безопасная очистка оперативной памяти
        secure_memory_clear(key_data);
        secure_memory_clear(in_data);
        secure_memory_clear(out_data);

    } catch (const CancelOperation& e) {
        cout << "\n[" << e.what() << " Возврат в меню...]\n" << endl;
        if (!temp_file_path.empty()) {
            std::remove(temp_file_path.c_str());
            cout << "[СИСТЕМА]: Созданный временный файл удален." << endl;
        }
    } catch (const exception& e) {
        cerr << "\n[ОШИБКА]: " << e.what() << "\n" << endl;
        if (!temp_file_path.empty()) std::remove(temp_file_path.c_str());
    }
}

void process_keygen(LoadedModule* mod) {
    try {
        string params;
        if (mod->name == "RSA") {
            cout << "Введите два простых числа через пробел (p q) [или 0 для отмены]: ";
        } else if (mod->name == "DiffieHellman") {
            cout << "Введите генератор, простое число и секретный ключ (g p a) через пробел [или 0 для отмены]: ";
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
            
            // ИСПРАВЛЕНО: Теперь текст меню выводится перед вызовом get_choice
            cout << "\nКак поступить со сгенерированными ключами?\n"
                 << "1. Вывести результаты в консоль\n"
                 << "2. Сохранить результаты в файл\n"
                 << "0. Отменить и выйти в меню\n";
            
            int save_choice = get_choice<int>(0, 2);
            if (save_choice == 0) throw CancelOperation();
            
            if (save_choice == 1) {
                cout << "\n>>> Данные вашего ключа:\n" << buffer << endl;
            } else {
                cout << "Введите путь для сохранения ключа: ";
                string path; 
                getline(cin, path);
                if (path == "0") throw CancelOperation();
                
                ofstream file(path, ios::binary);
                if (!file.is_open()) throw runtime_error("Не удалось создать файл ключа.");
                file.write(buffer, written);
                cout << ">>> Ключ успешно сохранен в файл: " << path << endl;
            }
        } else if (status == CryptoStatus::InvalidParam) {
            throw runtime_error("Неверные параметры модулей. Проверьте простоту чисел / формат.");
        } else {
            throw runtime_error("Внутренняя ошибка генерации.");
        }
    } catch (const CancelOperation& e) {
        cout << "\n[" << e.what() << " Возврат в меню...]\n" << endl;
    } catch (const exception& e) {
        cerr << "\n[ОШИБКА]: " << e.what() << "\n" << endl;
    }
}
