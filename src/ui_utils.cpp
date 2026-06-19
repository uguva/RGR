#include "ui_utils.h"
#include "sha256.h"
#include <iostream>
#include <fstream>
#include <cstdio>
#include <limits>
#include <stdexcept>
#include <iterator>

using std::cin;
using std::cout;
using std::endl;
using std::string;
using std::cerr;
using std::vector;
using std::ifstream;
using std::ofstream;
using std::ios;
using std::getline;
using std::exception;
using std::runtime_error;
using std::streamsize;
using std::numeric_limits;
using std::istreambuf_iterator;

const streamsize MAX_FILE_SIZE = 100 * 1024 * 1024; // Лимит 100 МБ

void clear_input() {
    cin.clear();
    cin.ignore((numeric_limits<streamsize>::max)(), '\n');
}

bool login() {
    string password;
    cout << "Введите пароль для доступа к системе: ";
    cin >> password;
    
    const string EXPECTED_HASH = "0322a97bd570f02468b9f6e3d524d7d303173c8cde7f0c0f543d50a7d31935e8";
    
    string input_hash = sha256(password);
    bool is_valid = (input_hash == EXPECTED_HASH);
    
    if (!password.empty()) {
        secure_memory_clear(reinterpret_cast<uint8_t*>(&password[0]), password.size());
    }
    
    return is_valid;
}

// Функция для безопасного удаления временного файла (затирание нулями перед удалением)
void safe_delete_file(const string& path) {
    if (path.empty()) return;
    ofstream file(path, ios::binary | ios::in | ios::out);
    if (file.is_open()) {
        file.seekp(0, ios::end);
        streamsize size = file.tellp();
        file.seekp(0, ios::beg);
        if (size > 0) {
            vector<char> zeros(size, 0);
            file.write(zeros.data(), size);
        }
        file.close();
    }
    std::remove(path.c_str());
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
        
        ifstream file(path, ios::binary | ios::ate);
        if (!file.is_open()) throw runtime_error("Не удалось открыть входной файл. Проверьте путь и права.");
        
        streamsize size = file.tellg();
        if (size > MAX_FILE_SIZE) throw runtime_error("Файл слишком велик (ограничение 100 МБ).");
        file.seekg(0, ios::beg);
        
        return vector<uint8_t>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    } else if (choice == 2) {
        cout << "Введите текст (или 0 для отмены): ";
        string text;
        getline(cin, text);
        if (text == "0") throw CancelOperation();
        
        vector<uint8_t> res(text.begin(), text.end());
        if (!text.empty()) secure_memory_clear(reinterpret_cast<uint8_t*>(&text[0]), text.size());
        return res;
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

        created_file_path = path;
        vector<uint8_t> res(text.begin(), text.end());
        if (!text.empty()) secure_memory_clear(reinterpret_cast<uint8_t*>(&text[0]), text.size());
        return res;
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
        
        ifstream file(path, ios::binary | ios::ate);
        if (!file.is_open()) throw runtime_error("Не удалось открыть файл ключа.");
        
        streamsize size = file.tellg();
        if (size > MAX_FILE_SIZE) throw runtime_error("Файл ключа слишком велик.");
        file.seekg(0, ios::beg);
        
        return vector<uint8_t>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    } else {
        if (algo_name == "RSA") {
            if (is_encrypt) cout << "Введите ключ (формат 'Public: e,n' или 'e,n') [или 0 для отмены]: ";
            else cout << "Введите ключ (формат 'Private: d,n' или 'd,n') [или 0 для отмены]: ";
        } else if (algo_name == "DiffieHellman") {
            cout << "Введите ключ (формат 'p g priv pub_enemy' через пробел) [или 0 для отмены]: ";
        } else if (algo_name == "Trithemius") {
            cout << "Введите ключ (числовой сдвиг) [или 0 для отмены]: ";
        } else {
            cout << "Введите ключ [или 0 для отмены]: ";
        }
        string text;
        getline(cin, text);
        if (text == "0") throw CancelOperation();
        
        vector<uint8_t> res(text.begin(), text.end());
        if (!text.empty()) secure_memory_clear(reinterpret_cast<uint8_t*>(&text[0]), text.size());
        return res;
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
        
        // Проверка на перезапись файла
        ifstream check_file(path);
        if (check_file.is_open()) {
            check_file.close();
            cout << "[ВНИМАНИЕ]: Файл уже существует. Перезаписать? (1 - Да, 0 - Отмена): ";
            int overwrite = get_choice<int>(0, 1);
            if (overwrite == 0) throw CancelOperation();
        }

        ofstream file(path, ios::binary);
        if (!file.is_open()) throw runtime_error("Не удалось создать файл для записи.");

        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        file.close();
        
        cout << ">>> Успешно! Файл сохранен: " << path << endl;
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

        secure_memory_clear(key_data);
        secure_memory_clear(in_data);
        secure_memory_clear(out_data);

    } catch (const CancelOperation& e) {
        cout << "\n[" << e.what() << " Возврат в меню...]\n" << endl;
        if (!temp_file_path.empty()) {
            safe_delete_file(temp_file_path);
            cout << "[СИСТЕМА]: Созданный временный файл удален." << endl;
        }
    } catch (const exception& e) {
        cerr << "\n[ОШИБКА]: " << e.what() << "\n" << endl;
        if (!temp_file_path.empty()) safe_delete_file(temp_file_path);
    }
}

void process_keygen(LoadedModule* mod) {
    if (!mod) return;

    string algo_name = mod->name;
    string params = "";

    // 1. Обработка ввода параметров (уникальная для каждого алгоритма)
    if (algo_name == "AES" || algo_name == "DES" || algo_name == "Affine") {
        params = "auto";
    } else {
        if (algo_name == "Vernam") {
            cout << "Введите длину ключа (число) [или 0 для отмены]: ";
        } else if (algo_name == "DiffieHellman") {
            cout << "Введите генератор, простое число и секретный ключ (g p a) через пробел [или 0 для отмены]: ";
        } else if (algo_name == "Blowfish") {
            cout << "Введите seed (строка) [или 0 для отмены]: ";
        } else if (algo_name == "Trithemius") {
            cout << "Введите seed (строка) [или 0 для отмены]: ";
        } else {
            // Для RSA или иных неизвестных алгоритмов
            cout << "Введите два простых числа через пробел (p q) [или 0 для отмены]: ";
        }
        
        getline(cin, params);
        if (params == "0") {
            cout << "Операция отменена." << endl;
            return;
        }
    }

    // 2. Генерация ключа (общая логика для всех)
    vector<char> buffer(4096, 0);
    size_t written = 0;
    CryptoStatus status = mod->generate_keys(params.c_str(), buffer.data(), buffer.size(), &written);
    // Безопасная очистка параметров из оперативной памяти
    if (!params.empty() && params != "auto") {
        secure_memory_clear(reinterpret_cast<uint8_t*>(&params[0]), params.size());
    }

    if (status != CryptoStatus::Success) {
        cout << "[ОШИБКА]: Сбой генерации ключа. Код: " << static_cast<int>(status) << endl;
        return;
    }

    string key_str(buffer.data(), written);
    cout << "\n>>> Ключи успешно сгенерированы!\n" << endl;

    // 3. Вывод/Сохранение (общая логика для всех)
    cout << "Как поступить со сгенерированными ключами?\n";
    cout << "1. Вывести результаты в консоль\n";
    cout << "2. Сохранить результаты в файл\n";
    cout << "0. Отменить и выйти в меню\n";
    cout << "Выбор: ";
    
    int choice = get_choice<int>(0, 2);
    
    if (choice == 1) {
        cout << "\n>>> Данные вашего ключа:\n" << key_str << "\n" << endl;
    } else if (choice == 2) {
        cout << "Введите имя файла для сохранения: ";
        string filepath;
        getline(cin, filepath);
        
        ofstream out(filepath, std::ios::binary);
        if (out.is_open()) {
            out.write(key_str.c_str(), key_str.size());
            cout << "[*] Ключи успешно сохранены в файл: " << filepath << endl;
        } else {
            cout << "[ОШИБКА]: Не удалось записать данные в файл." << endl;
        }
    }
    
    // 4. Очистка ключа из памяти (безопасность!)
    if (!key_str.empty()) {
        secure_memory_clear(reinterpret_cast<uint8_t*>(&key_str[0]), key_str.size());
    }
}

void run_sub_menu(LoadedModule* mod, const string& menu_name) {
    if (!mod) {
        std::cerr << "[ОШИБКА]: Модуль " << menu_name << " не загружен!" << endl; 
        return; 
    }
    
    enum class SubMenuOption { Back = 0, Keygen = 1, Encrypt = 2, Decrypt = 3 };

    while (true) {
        cout << "\n--- Меню: " << menu_name << " ---" << endl;
        cout << "1. Сгенерировать ключи\n2. Зашифровать данные\n3. Расшифровать данные\n0. Назад\nВыбор: ";
        
        SubMenuOption sub = static_cast<SubMenuOption>(get_choice<int>(0, 3));
        switch (sub) {
            case SubMenuOption::Keygen:  process_keygen(mod); break;
            case SubMenuOption::Encrypt: process_crypto(mod, true); break;
            case SubMenuOption::Decrypt: process_crypto(mod, false); break;
            case SubMenuOption::Back:    return;
        }
    }
}
