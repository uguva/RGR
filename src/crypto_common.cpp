#include "../include/crypto_common.h"
#include "../include/affine_cipher.h"
#include "../include/vernam_cipher.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <dlfcn.h>

using namespace std;

struct LoadedLibrary {
    void* handle;
    int (*generate_key)(uint8_t*, size_t);
    int (*encrypt)(const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t*);
    int (*decrypt)(const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t*);
    size_t expected_key_size;
};

static LoadedLibrary load_cipher_library(Algorithm cipher) {
    LoadedLibrary lib = {nullptr, nullptr, nullptr, nullptr, 0};
    const char* library_path = nullptr;
    const char* encrypt_function_name = nullptr;
    const char* decrypt_function_name = nullptr;
    const char* generate_function_name = nullptr;
    
    switch (cipher) {
        case Algorithm::AFFINE:
            library_path = "./lib/libaffine.so";
            encrypt_function_name = "affine_encrypt";
            decrypt_function_name = "affine_decrypt";
            generate_function_name = "affine_generate_key";
            lib.expected_key_size = 2;
            break;
        case Algorithm::VERNAM:
            library_path = "./lib/libvernam.so";
            encrypt_function_name = "vernam_encrypt";
            decrypt_function_name = "vernam_decrypt";
            generate_function_name = "vernam_generate_key";
            lib.expected_key_size = 0;
            break;
        default:
            cerr << "Ошибка: неизвестный алгоритм\n";
            return lib;
    }
    
    lib.handle = dlopen(library_path, RTLD_LAZY);
    if (!lib.handle) {
        cerr << "Ошибка: не удалось загрузить " << library_path << "\n";
        return lib;
    }
    
    lib.generate_key = (int(*)(uint8_t*, size_t))dlsym(lib.handle, generate_function_name);
    lib.encrypt = (int(*)(const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t*))dlsym(lib.handle, encrypt_function_name);
    lib.decrypt = (int(*)(const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t*))dlsym(lib.handle, decrypt_function_name);
    
    if (!lib.generate_key || !lib.encrypt || !lib.decrypt) {
        cerr << "Ошибка: в библиотеке " << library_path << " нет нужных функций\n";
        dlclose(lib.handle);
        lib.handle = nullptr;
    }
    
    return lib;
}

static vector<uint8_t> read_binary_file(const string& file_path) {
    ifstream file(file_path, ios::binary);
    if (!file) return {};
    return vector<uint8_t>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
}

static bool write_binary_file(const string& file_path, const vector<uint8_t>& data) {
    ofstream file(file_path, ios::binary);
    if (!file) return false;
    file.write((const char*)data.data(), data.size());
    return true;
}

void print_error(int error_code) {
    switch (error_code) {
        case 1: cerr << "Ошибка: ключ слишком короткий\n"; break;
        case 2: cerr << "Ошибка: выходной буфер слишком мал\n"; break;
        case 3: cerr << "Ошибка: неверные параметры ключа\n"; break;
        case 4: cerr << "Ошибка: не удалось загрузить библиотеку\n"; break;
        case 5: cerr << "Ошибка: не удалось прочитать файл\n"; break;
        case 6: cerr << "Ошибка: не удалось записать файл\n"; break;
        default: cerr << "Ошибка: неизвестный код " << error_code << "\n"; break;
    }
}

int generate_key_affine(const string& output_file) {
    LoadedLibrary lib = load_cipher_library(Algorithm::AFFINE);
    if (!lib.handle) return 4;
    
    vector<uint8_t> key(2);
    int result = lib.generate_key(key.data(), key.size());
    if (result != 0) {
        print_error(result);
        dlclose(lib.handle);
        return result;
    }
    
    if (!write_binary_file(output_file, key)) {
        dlclose(lib.handle);
        return 6;
    }
    
    cout << "Ключ аффинного шифра (2 байта) сохранён в " << output_file << "\n";
    dlclose(lib.handle);
    return 0;
}

int generate_key_vernam(const string& output_file, size_t key_size) {
    if (key_size == 0) {
        cerr << "Ошибка: размер ключа должен быть больше 0\n";
        return 1;
    }
    
    LoadedLibrary lib = load_cipher_library(Algorithm::VERNAM);
    if (!lib.handle) return 4;
    
    vector<uint8_t> key(key_size);
    int result = lib.generate_key(key.data(), key.size());
    if (result != 0) {
        print_error(result);
        dlclose(lib.handle);
        return result;
    }
    
    if (!write_binary_file(output_file, key)) {
        dlclose(lib.handle);
        return 6;
    }
    
    cout << "Ключ Вернама (" << key_size << " байт) сохранён в " << output_file << "\n";
    dlclose(lib.handle);
    return 0;
}

int encrypt_file(Algorithm cipher, const string& input_file,
                 const string& output_file, const string& key_file) {
    LoadedLibrary lib = load_cipher_library(cipher);
    if (!lib.handle) return 4;
    
    vector<uint8_t> plain_data = read_binary_file(input_file);
    if (plain_data.empty()) {
        dlclose(lib.handle);
        return 5;
    }
    
    vector<uint8_t> key_data = read_binary_file(key_file);
    if (key_data.empty()) {
        dlclose(lib.handle);
        return 1;
    }
    
    if (cipher == Algorithm::VERNAM) {
        if (key_data.size() < plain_data.size()) {
            cerr << "Ошибка: ключ короче файла. Нужно " << plain_data.size() << " байт, есть " << key_data.size() << "\n";
            dlclose(lib.handle);
            return 1;
        }
    }
    else if (cipher == Algorithm::AFFINE) {
        if (key_data.size() != 2) {
            cerr << "Ошибка: ключ аффинного шифра должен быть 2 байта\n";
            dlclose(lib.handle);
            return 1;
        }
    }
    
    vector<uint8_t> cipher_data(plain_data.size());
    size_t cipher_length = cipher_data.size();
    
    int result = lib.encrypt(plain_data.data(), plain_data.size(),key_data.data(), key_data.size(),cipher_data.data(), &cipher_length);
    
    if (result != 0) {
        print_error(result);
        dlclose(lib.handle);
        return result;
    }
    
    cipher_data.resize(cipher_length);
    if (!write_binary_file(output_file, cipher_data)) {
        dlclose(lib.handle);
        return 6;
    }
    
    cout << "Зашифровано " << plain_data.size() << " байт -> " << output_file << "\n";
    dlclose(lib.handle);
    return 0;
}

int decrypt_file(Algorithm cipher, const string& input_file,const string& output_file, const string& key_file) {
    LoadedLibrary lib = load_cipher_library(cipher);
    if (!lib.handle) return 4;
    
    vector<uint8_t> cipher_data = read_binary_file(input_file);
    if (cipher_data.empty()) {
        dlclose(lib.handle);
        return 5;
    }
    
    vector<uint8_t> key_data = read_binary_file(key_file);
    if (key_data.empty()) {
        dlclose(lib.handle);
        return 1;
    }
    
    if (cipher == Algorithm::VERNAM) {
        if (key_data.size() < cipher_data.size()) {
            cerr << "Ошибка: ключ короче файла. Нужно " << cipher_data.size() << " байт, есть " << key_data.size() << "\n";
            dlclose(lib.handle);
            return 1;
        }
    }
    else if (cipher == Algorithm::AFFINE) {
        if (key_data.size() != 2) {
            cerr << "Ошибка: ключ аффинного шифра должен быть 2 байта\n";
            dlclose(lib.handle);
            return 1;
        }
    }
    
    vector<uint8_t> plain_data(cipher_data.size());
    size_t plain_length = plain_data.size();
    
    int result = lib.decrypt(cipher_data.data(), cipher_data.size(),key_data.data(), key_data.size(),plain_data.data(), &plain_length);
    
    if (result != 0) {
        print_error(result);
        dlclose(lib.handle);
        return result;
    }
    
    plain_data.resize(plain_length);
    if (!write_binary_file(output_file, plain_data)) {
        dlclose(lib.handle);
        return 6;
    }
    
    cout << "Расшифровано " << cipher_data.size() << " байт -> " << output_file << "\n";
    dlclose(lib.handle);
    return 0;
}

int encrypt_text(Algorithm cipher, const string& input_text,
                 const string& key_file, vector<uint8_t>& output) {
    LoadedLibrary lib = load_cipher_library(cipher);
    if (!lib.handle) return 4;
    
    vector<uint8_t> plain_data(input_text.begin(), input_text.end());
    
    vector<uint8_t> key_data = read_binary_file(key_file);
    if (key_data.empty()) {
        dlclose(lib.handle);
        return 1;
    }
    
    if (cipher == Algorithm::VERNAM) {
        if (key_data.size() < plain_data.size()) {
            cerr << "Ошибка: ключ короче текста. Нужно " << plain_data.size() << " байт, есть " << key_data.size() << "\n";
            dlclose(lib.handle);
            return 1;
        }
    }
    else if (cipher == Algorithm::AFFINE) {
        if (key_data.size() != 2) {
            cerr << "Ошибка: ключ аффинного шифра должен быть 2 байта\n";
            dlclose(lib.handle);
            return 1;
        }
    }
    
    output.resize(plain_data.size());
    size_t output_length = output.size();
    
    int result = lib.encrypt(plain_data.data(), plain_data.size(),key_data.data(), key_data.size(),output.data(), &output_length);
    
    if (result != 0) {
        print_error(result);
        dlclose(lib.handle);
        return result;
    }
    
    output.resize(output_length);
    dlclose(lib.handle);
    return 0;
}

int decrypt_text(Algorithm cipher, const vector<uint8_t>& input,
                 const string& key_file, string& output_text) {
    LoadedLibrary lib = load_cipher_library(cipher);
    if (!lib.handle) return 4;
    
    vector<uint8_t> key_data = read_binary_file(key_file);
    if (key_data.empty()) {
        dlclose(lib.handle);
        return 1;
    }
    
    if (cipher == Algorithm::VERNAM) {
        if (key_data.size() < input.size()) {
            cerr << "Ошибка: ключ короче данных. Нужно " << input.size() << " байт, есть " << key_data.size() << "\n";
            dlclose(lib.handle);
            return 1;
        }
    }
    else if (cipher == Algorithm::AFFINE) {
        if (key_data.size() != 2) {
            cerr << "Ошибка: ключ аффинного шифра должен быть 2 байта\n";
            dlclose(lib.handle);
            return 1;
        }
    }
    
    vector<uint8_t> plain_data(input.size());
    size_t plain_length = plain_data.size();
    
    int result = lib.decrypt(input.data(), input.size(),key_data.data(), key_data.size(),plain_data.data(), &plain_length);
    
    if (result != 0) {
        print_error(result);
        dlclose(lib.handle);
        return result;
    }
    
    plain_data.resize(plain_length);
    output_text = string(plain_data.begin(), plain_data.end());
    dlclose(lib.handle);
    return 0;
}