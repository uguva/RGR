#include "module_manager.h"

#include <cctype>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

enum class MenuAction {
    EncryptText = 1,
    DecryptText = 2,
    EncryptFile = 3,
    DecryptFile = 4,
    ExitProgram = 5
};

enum class CipherType {
    Trithemius = 1,
    Blowfish = 2
};

bool login() {
    const string correct_password = "456654";
    string entered_password;

    cout << "Введите пароль для доступа к программе: ";
    getline(cin, entered_password);

    if (entered_password != correct_password) {
        cout << "Ошибка доступа. Неверный пароль." << endl;
        return false;
    }

    cout << "Доступ разрешен." << endl;
    return true;
}

vector<uint8_t> string_to_bytes(const string& input_text) {
    return vector<uint8_t>(input_text.begin(), input_text.end());
}

string bytes_to_string(const vector<uint8_t>& input_data) {
    return string(input_data.begin(), input_data.end());
}

string bytes_to_hex(const vector<uint8_t>& input_data) {
    stringstream hex_stream;

    for (uint8_t current_byte : input_data) {
        hex_stream << hex << setw(2) << setfill('0') << static_cast<int>(current_byte) << ' ';
    }

    return hex_stream.str();
}

vector<uint8_t> hex_to_bytes(const string& hex_text) {
    vector<uint8_t> output_data;
    string cleaned_text;

    for (char current_character : hex_text) {
        if (!isspace(static_cast<unsigned char>(current_character))) {
            cleaned_text.push_back(current_character);
        }
    }

    if (cleaned_text.size() % 2 != 0) {
        throw invalid_argument("Количество шестнадцатеричных символов должно быть четным");
    }

    for (size_t text_index = 0; text_index < cleaned_text.size(); text_index += 2) {
        string byte_text = cleaned_text.substr(text_index, 2);
        uint8_t current_byte = static_cast<uint8_t>(stoi(byte_text, nullptr, 16));
        output_data.push_back(current_byte);
    }

    return output_data;
}

vector<uint8_t> read_file_bytes(const string& file_path) {
    ifstream input_file(file_path, ios::binary);

    if (!input_file) {
        throw runtime_error("Не удалось открыть входной файл: " + file_path);
    }

    return vector<uint8_t>((istreambuf_iterator<char>(input_file)), istreambuf_iterator<char>());
}

void write_file_bytes(const string& file_path, const vector<uint8_t>& output_data) {
    ofstream output_file(file_path, ios::binary);

    if (!output_file) {
        throw runtime_error("Не удалось открыть выходной файл: " + file_path);
    }

    output_file.write(reinterpret_cast<const char*>(output_data.data()), static_cast<streamsize>(output_data.size()));
}

string create_encrypted_file_path(const string& input_path) {
    return input_path + ".enc";
}

string create_decrypted_file_path(const string& encrypted_path) {
    const string encrypted_extension = ".enc";

    if (encrypted_path.size() > encrypted_extension.size() &&
        encrypted_path.substr(encrypted_path.size() - encrypted_extension.size()) == encrypted_extension) {
        return encrypted_path.substr(0, encrypted_path.size() - encrypted_extension.size());
    }

    return encrypted_path + ".dec";
}

int read_number_from_console() {
    string input_line;
    getline(cin, input_line);
    return stoi(input_line);
}

IEncryptionModule* choose_cipher(ModuleManager& module_manager) {
    cout << "Выберите шифр:" << endl;
    cout << "1. Шифр Тритемия" << endl;
    cout << "2. Blowfish" << endl;
    cout << "Ваш выбор: ";

    CipherType selected_cipher = static_cast<CipherType>(read_number_from_console());

    switch (selected_cipher) {
        case CipherType::Trithemius:
            return module_manager.get_module("Trithemius");
        case CipherType::Blowfish:
            return module_manager.get_module("Blowfish");
        default:
            return nullptr;
    }
}

void encrypt_text(ModuleManager& module_manager) {
    IEncryptionModule* selected_module = choose_cipher(module_manager);

    if (selected_module == nullptr) {
        cout << "Шифр не найден." << endl;
        return;
    }

    string input_text;
    string key_text;

    cout << "Введите текст для шифрования: ";
    getline(cin, input_text);
    cout << "Введите ключ: ";
    getline(cin, key_text);

    vector<uint8_t> encrypted_data = selected_module->encrypt(string_to_bytes(input_text), key_text);
    cout << "Результат в HEX: " << bytes_to_hex(encrypted_data) << endl;
}

void decrypt_text(ModuleManager& module_manager) {
    IEncryptionModule* selected_module = choose_cipher(module_manager);

    if (selected_module == nullptr) {
        cout << "Шифр не найден." << endl;
        return;
    }

    string encrypted_hex_text;
    string key_text;

    cout << "Введите зашифрованные данные в HEX: ";
    getline(cin, encrypted_hex_text);
    cout << "Введите ключ: ";
    getline(cin, key_text);

    vector<uint8_t> encrypted_data = hex_to_bytes(encrypted_hex_text);
    vector<uint8_t> decrypted_data = selected_module->decrypt(encrypted_data, key_text);
    cout << "Расшифрованный текст: " << bytes_to_string(decrypted_data) << endl;
}

void encrypt_file(ModuleManager& module_manager) {
    IEncryptionModule* selected_module = choose_cipher(module_manager);

    if (selected_module == nullptr) {
        cout << "Шифр не найден." << endl;
        return;
    }

    string input_file_path;
    string key_text;

    cout << "Введите путь к файлу с расширением: ";
    getline(cin, input_file_path);
    cout << "Введите ключ: ";
    getline(cin, key_text);

    vector<uint8_t> input_data = read_file_bytes(input_file_path);
    vector<uint8_t> encrypted_data = selected_module->encrypt(input_data, key_text);
    string output_file_path = create_encrypted_file_path(input_file_path);

    write_file_bytes(output_file_path, encrypted_data);
    cout << "Файл зашифрован: " << output_file_path << endl;
}

void decrypt_file(ModuleManager& module_manager) {
    IEncryptionModule* selected_module = choose_cipher(module_manager);

    if (selected_module == nullptr) {
        cout << "Шифр не найден." << endl;
        return;
    }

    string encrypted_file_path;
    string key_text;

    cout << "Введите путь к файлу .enc: ";
    getline(cin, encrypted_file_path);
    cout << "Введите ключ: ";
    getline(cin, key_text);

    vector<uint8_t> encrypted_data = read_file_bytes(encrypted_file_path);
    vector<uint8_t> decrypted_data = selected_module->decrypt(encrypted_data, key_text);
    string output_file_path = create_decrypted_file_path(encrypted_file_path);

    write_file_bytes(output_file_path, decrypted_data);
    cout << "Файл расшифрован: " << output_file_path << endl;
}

void show_menu() {
    cout << endl;
    cout << "Главное меню" << endl;
    cout << "1. Зашифровать текст" << endl;
    cout << "2. Расшифровать текст" << endl;
    cout << "3. Зашифровать файл" << endl;
    cout << "4. Расшифровать файл" << endl;
    cout << "5. Выход" << endl;
    cout << "Ваш выбор: ";
}

int main() {
    setlocale(LC_ALL, "ru_RU.UTF-8");

    if (!login()) {
        return 0;
    }

    ModuleManager module_manager;

    if (!module_manager.load_module("./libtrithemius.so") ||
        !module_manager.load_module("./libblowfish.so")) {
        cout << "Ошибка инициализации криптографических библиотек." << endl;
        return 1;
    }

    bool program_running = true;

    while (program_running) {
        try {
            show_menu();
            MenuAction selected_action = static_cast<MenuAction>(read_number_from_console());

            switch (selected_action) {
                case MenuAction::EncryptText:
                    encrypt_text(module_manager);
                    break;
                case MenuAction::DecryptText:
                    decrypt_text(module_manager);
                    break;
                case MenuAction::EncryptFile:
                    encrypt_file(module_manager);
                    break;
                case MenuAction::DecryptFile:
                    decrypt_file(module_manager);
                    break;
                case MenuAction::ExitProgram:
                    program_running = false;
                    break;
                default:
                    cout << "Некорректный пункт меню." << endl;
                    break;
            }
        } catch (const exception& error) {
            cout << "Ошибка: " << error.what() << endl;
        }
    }

    cout << "Программа завершена." << endl;
    return 0;
}
