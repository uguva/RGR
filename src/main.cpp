#include "../include/crypto_common.h"
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <iomanip>

using namespace std;

bool login() {
    string password;
    cout << "Введите пароль: ";
    cin >> password;
    return password == "suhanov521";
}

void print_hex(const vector<uint8_t>& data) {
    for (size_t i = 0; i < data.size(); i++) {
        cout << hex << setw(2) << setfill('0') << (int)data[i] << " ";
        if ((i + 1) % 16 == 0) cout << "\n";
    }
    cout << dec << endl;
}

Algorithm string_to_algorithm(const string& name) {
    if (name == "affine") return Algorithm::AFFINE;
    if (name == "vernam") return Algorithm::VERNAM;
    return Algorithm::AFFINE;
}

int main() {
    if (!login()) {
        cout << "Неверный пароль. Доступ запрещён.\n";
        return 1;
    }

    int choice, subchoice;
    string cipher_name, key_file, input_text, output_text;
    string input_file, output_file;
    vector<uint8_t> encrypted_data;
    
    while (true) {
        cout << "\nКРИПТОИНСТРУМЕНТ\n";
        cout << "1. Работа с файлом\n";
        cout << "2. Работа с текстом (клавиатура)\n";
        cout << "3. Выход\n";
        cout << "Выберите: ";
        cin >> choice;
        
        if (choice == 3) {
            cout << "До свидания!\n";
            break;
        }
        
        if (choice == 1) {
            cout << "\n1. Сгенерировать ключ (affine)\n";
            cout << "2. Сгенерировать ключ (vernam)\n";
            cout << "3. Зашифровать файл\n";
            cout << "4. Расшифровать файл\n";
            cout << "Выберите: ";
            cin >> subchoice;
            
            if (subchoice == 1) {
                cout << "Файл для ключа: ";
                cin >> key_file;
                generate_key_affine(key_file);
            }
            else if (subchoice == 2) {
                cout << "Файл для ключа: ";
                cin >> key_file;
                cout << "Размер ключа в байтах: ";
                size_t ks; cin >> ks;
                generate_key_vernam(key_file, ks);
            }
            else if (subchoice == 3) {
                cout << "Шифр (affine/vernam): ";
                cin >> cipher_name;
                cout << "Входной файл: ";
                cin >> input_file;
                cout << "Выходной файл: ";
                cin >> output_file;
                cout << "Файл с ключом: ";
                cin >> key_file;
                encrypt_file(string_to_algorithm(cipher_name), input_file, output_file, key_file);
            }
            else if (subchoice == 4) {
                cout << "Шифр (affine/vernam): ";
                cin >> cipher_name;
                cout << "Входной файл: ";
                cin >> input_file;
                cout << "Выходной файл: ";
                cin >> output_file;
                cout << "Файл с ключом: ";
                cin >> key_file;
                decrypt_file(string_to_algorithm(cipher_name), input_file, output_file, key_file);
            }
        }
        else if (choice == 2) {
            cout << "\n1. Сгенерировать ключ (affine)\n";
            cout << "2. Сгенерировать ключ (vernam)\n";
            cout << "3. Зашифровать текст\n";
            cout << "4. Расшифровать текст\n";
            cout << "Выберите: ";
            cin >> subchoice;
            
            if (subchoice == 1) {
                cout << "Файл для ключа: ";
                cin >> key_file;
                generate_key_affine(key_file);
            }
            else if (subchoice == 2) {
                cout << "Файл для ключа: ";
                cin >> key_file;
                cout << "Размер ключа в байтах: ";
                size_t ks; cin >> ks;
                generate_key_vernam(key_file, ks);
            }
            else if (subchoice == 3) {
                cout << "Шифр (affine/vernam): ";
                cin >> cipher_name;
                cout << "Файл с ключом: ";
                cin >> key_file;
                cin.ignore();
                cout << "Введите текст: ";
                getline(cin, input_text);
                
                int res = encrypt_text(string_to_algorithm(cipher_name), input_text, key_file, encrypted_data);
                if (res == 0) {
                    cout << "\nHEX: ";
                    print_hex(encrypted_data);
                    cout << "DEC: ";
                    for (size_t i = 0; i < encrypted_data.size(); i++) {
                        cout << (int)encrypted_data[i] << " ";
                    }
                    cout << "\n";
                }
            }
            else if (subchoice == 4) {
                cout << "Шифр (affine/vernam): ";
                cin >> cipher_name;
                cout << "Файл с ключом: ";
                cin >> key_file;
                cout << "Введите зашифрованные байты (в десятичном виде, через пробел, в конце Enter):\n";
                
                encrypted_data.clear();
                int val;
                while (cin >> val) {
                    encrypted_data.push_back((uint8_t)val);
                    if (cin.peek() == '\n') break;
                }
                
                int res = decrypt_text(string_to_algorithm(cipher_name), encrypted_data, key_file, output_text);
                if (res == 0) {
                    cout << "Текст: " << output_text << "\n";
                }
                cin.clear();
            }
        }
    }
    
    return 0;
}