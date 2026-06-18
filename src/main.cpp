#include "encrypto.h"
#include "crypto_common.h"

#include <filesystem>
#include <iostream>
#include <string>

using namespace std;
namespace fs = std::filesystem;

namespace {

enum class DataMode
{
    None = 0,
    Text = 1,
    File = 2
};

enum class WorkMode
{
    None = 0,
    Encrypt = 1,
    Decrypt = 2
};

enum class MenuItem
{
    Exit = 0,
    SelectDataMode = 1,
    SelectWorkMode = 2,
    SelectAlgorithm = 3,
    InputSourceData = 4,
    InputOutputPath = 5,
    GenerateKey = 6,
    RunOperation = 7
};

string dataModeToString(DataMode mode)
{
    switch (mode)
    {
        case DataMode::Text: return "Текст";
        case DataMode::File: return "Файл";
        default: return "Не выбрано";
    }
}

string workModeToString(WorkMode mode)
{
    switch (mode)
    {
        case WorkMode::Encrypt: return "Шифрование";
        case WorkMode::Decrypt: return "Дешифрование";
        default: return "Не выбрано";
    }
}

string algoName(crypto::Algorithm algo)
{
    return crypto::algorithmToString(algo);
}

string bytesToHex(const vector<uint8_t>& data)
{
    static const char* digits = "0123456789ABCDEF";
    string result;
    result.reserve(data.size() * 2);

    for (uint8_t byte : data)
    {
        result.push_back(digits[(byte >> 4) & 0x0F]);
        result.push_back(digits[byte & 0x0F]);
    }

    return result;
}


string makeKeyFilePath(const string& outputPath)
{
    fs::path p = fs::u8path(outputPath);
    if (p.has_extension())
        return (p.parent_path() / (p.stem().u8string() + ".key")).u8string();

    return (p.u8string() + ".key");
}

bool saveKeyToFile(const string& outputPath, const string& keyText)
{
    string error;
    string keyPath = makeKeyFilePath(outputPath);

    if (!crypto::writeTextFile(keyPath, keyText, error))
    {
        cout << "Не удалось сохранить ключ в файл: " << error << endl;
        return false;
    }

    cout << "Ключ сохранён в файл: " << keyPath << endl;
    return true;
}

bool loadKeyFromFile(const string& keyPath, string& keyText)
{
    string error;
    if (!crypto::readTextFile(keyPath, keyText, error))
    {
        cout << "Не удалось прочитать ключ из файла: " << error << endl;
        return false;
    }

    while (!keyText.empty() && (keyText.back() == '\n' || keyText.back() == '\r' || isspace(static_cast<unsigned char>(keyText.back()))))
        keyText.pop_back();

    cout << "Ключ загружен из файла: " << keyPath << endl;
    return true;
}

bool askLine(const string& prompt, string& value)
{
    while (true)
    {
        cout << prompt << endl;

        if (!getline(cin, value))
            return false;

        if (!value.empty())
            return true;

        cout << "Ошибка: поле не должно быть пустым." << endl;
    }
}

bool askChoice(const string& prompt, int minValue, int maxValue, int& choice)
{
    while (true)
    {
        cout << prompt << endl;

        string input;
        if (!getline(cin, input))
            return false;

        try
        {
            size_t pos = 0;
            int value = stoi(input, &pos);

            if (pos != input.size())
                throw invalid_argument("extra");

            if (value < minValue || value > maxValue)
            {
                cout << "Ошибка: введите число от " << minValue << " до " << maxValue << "." << endl;
                continue;
            }

            choice = value;
            return true;
        }
        catch (const exception&)
        {
            cout << "Ошибка: необходимо ввести число." << endl;
        }
    }
}

bool fileExists(const string& path)
{
    error_code ec;
    fs::path p = fs::u8path(path);
    return fs::exists(p, ec) && fs::is_regular_file(p, ec);
}

bool ensureOutputPath(const string& path, string& message)
{
    error_code ec;
    fs::path p = fs::u8path(path);

    if (path.empty())
    {
        message = "Путь вывода не должен быть пустым.";
        return false;
    }

    if (fs::exists(p, ec) && fs::is_directory(p, ec))
    {
        message = "Указан путь к каталогу, а не к файлу.";
        return false;
    }

    fs::path parent = p.parent_path();
    if (!parent.empty() && !fs::exists(parent, ec))
    {
        if (!fs::create_directories(parent, ec) || ec)
        {
            message = "Не удалось создать каталог для выходного файла.";
            return false;
        }
    }

    return true;
}

void printBanner()
{
    cout << endl;
    cout << "========================================" << endl;
    cout << "      СИСТЕМА ШИФРОВАНИЯ ФАЙЛОВ" << endl;
    cout << "========================================" << endl;
}

void printMenu(DataMode dataMode,
               bool hasDataMode,
               WorkMode workMode,
               bool hasWorkMode,
               crypto::Algorithm algorithm,
               bool hasAlgorithm,
               const string& sourceData,
               bool hasSourceData,
               const string& outputPath,
               bool hasOutputPath,
               bool hasKey,
               const string& currentKey)
{
    printBanner();

    cout << "Текущие параметры:" << endl;
    cout << "  Тип данных : " << (hasDataMode ? dataModeToString(dataMode) : "Не выбрано") << endl;
    cout << "  Режим      : " << (hasWorkMode ? workModeToString(workMode) : "Не выбрано") << endl;
    cout << "  Алгоритм   : " << (hasAlgorithm ? algoName(algorithm) : "Не выбрано") << endl;

    if (hasDataMode && hasDataMode && dataMode == DataMode::Text)
        cout << "  Текст      : " << (hasSourceData ? sourceData : "Не введён") << endl;
    else
        cout << "  Исходный   : " << (hasSourceData ? sourceData : "Не выбрано") << endl;

    cout << "  Результат  : " << (hasOutputPath ? outputPath : "Не выбрано") << endl;
    cout << "  Ключ       : " << (hasKey ? "Сгенерирован / введён" : "Не выбран") << endl;

    if (hasKey && !currentKey.empty())
        cout << "  Ключ (HEX) : " << currentKey << endl;

    cout << endl;
    cout << "1 - Выбрать тип данных (текст / файл)" << endl;
    cout << "2 - Выбрать режим работы (шифрование / дешифрование)" << endl;
    cout << "3 - Выбрать алгоритм (AES / DES)" << endl;
    cout << "4 - Ввести исходный текст / выбрать исходный файл" << endl;
    cout << "5 - Указать результат (для файла или при необходимости сохранить текст)" << endl;
    cout << "6 - Сгенерировать ключ" << endl;
    cout << "7 - Запустить операцию" << endl;
    cout << "0 - Выход" << endl;
    cout << "========================================" << endl;
}

bool chooseDataMode(DataMode& dataMode, bool& hasDataMode)
{
    int choice = 0;
    if (!askChoice("Выберите тип данных:\n1 - Текст\n2 - Файл", 1, 2, choice))
        return false;

    dataMode = (choice == 1) ? DataMode::Text : DataMode::File;
    hasDataMode = true;
    cout << "Выбран тип данных: " << dataModeToString(dataMode) << endl;
    return true;
}

bool chooseWorkMode(WorkMode& workMode, bool& hasWorkMode)
{
    int choice = 0;
    if (!askChoice("Выберите режим:\n1 - Шифрование\n2 - Дешифрование", 1, 2, choice))
        return false;

    workMode = (choice == 1) ? WorkMode::Encrypt : WorkMode::Decrypt;
    hasWorkMode = true;
    cout << "Выбран режим: " << workModeToString(workMode) << endl;
    return true;
}

bool chooseAlgorithm(crypto::Algorithm& algorithm, bool& hasAlgorithm, string& currentKey, bool& hasKey)
{
    int choice = 0;
    if (!askChoice("Выберите алгоритм:\n1 - AES\n2 - DES", 1, 2, choice))
        return false;

    algorithm = (choice == 1) ? crypto::Algorithm::AES : crypto::Algorithm::DES;
    hasAlgorithm = true;
    hasKey = false;
    currentKey.clear();
    cout << "Выбран алгоритм: " << algoName(algorithm) << endl;
    return true;
}

bool inputSourceData(DataMode dataMode, string& sourceData, bool& hasSourceData)
{
    if (dataMode == DataMode::Text)
    {
        if (!askLine("Введите исходный текст:", sourceData))
            return false;

        hasSourceData = true;
        cout << "Текст введён." << endl;
        return true;
    }

    while (true)
    {
        if (!askLine("Введите путь к исходному файлу:", sourceData))
            return false;

        if (!fileExists(sourceData))
        {
            cout << "Ошибка: файл не существует. Проверьте путь и попробуйте снова." << endl;
            continue;
        }

        hasSourceData = true;
        cout << "Исходный файл выбран: " << sourceData << endl;
        return true;
    }
}

bool inputOutputPath(DataMode dataMode, string& outputPath, bool& hasOutputPath)
{
    if (dataMode == DataMode::Text)
    {
        cout << "Введите путь для дополнительного сохранения результата (или оставьте пустым):" << endl;
        if (!getline(cin, outputPath))
            return false;

        if (outputPath.empty())
        {
            hasOutputPath = false;
            cout << "Результат будет выведен только в консоль." << endl;
            return true;
        }

        string message;
        if (!ensureOutputPath(outputPath, message))
        {
            cout << "Ошибка: " << message << endl;
            return true;
        }

        hasOutputPath = true;
        cout << "Результат будет дополнительно сохранён в файл: " << outputPath << endl;
        return true;
    }

    while (true)
    {
        if (!askLine("Введите путь к выходному файлу:", outputPath))
            return false;

        string message;
        if (!ensureOutputPath(outputPath, message))
        {
            cout << "Ошибка: " << message << endl;
            continue;
        }

        hasOutputPath = true;
        cout << "Выходной файл: " << outputPath << endl;
        return true;
    }
}

void generateKeyForSelectedAlgorithm(crypto::Algorithm algorithm,
                                      const string& outputPath,
                                      string& currentKey,
                                      bool& hasKey)
{
    currentKey = crypto::generateKeyHex(algorithm);
    hasKey = true;

    cout << endl;
    cout << "========================================" << endl;
    cout << "СГЕНЕРИРОВАН КЛЮЧ" << endl;
    cout << "Алгоритм: " << algoName(algorithm) << endl;
    cout << "Ключ (HEX): " << currentKey << endl;
    cout << "Ключ будет сохранён в отдельный файл." << endl;
    cout << "========================================" << endl;

    if (!outputPath.empty())
        saveKeyToFile(outputPath, currentKey);
}



bool readKeyOrKeyFile(string& currentKey, bool& hasKey)
{
    cout << "Введите ключ вручную или путь к файлу ключа (.key):" << endl;

    string value;
    if (!getline(cin, value))
        return false;

    if (value.empty())
    {
        cout << "Ошибка: ключ не должен быть пустым." << endl;
        return false;
    }

    if (value.size() >= 4 && value.substr(value.size() - 4) == ".key")
    {
        if (!loadKeyFromFile(value, currentKey))
            return false;
        hasKey = true;
        return true;
    }

    currentKey = value;
    hasKey = true;
    return true;
}

bool readKeyFromUser(string& currentKey, bool& hasKey)
{
    if (!askLine("Введите ключ, полученный при шифровании:", currentKey))
        return false;

    hasKey = true;
    return true;
}

bool performFileOperation(WorkMode workMode,
                          crypto::Algorithm algorithm,
                          const string& sourceData,
                          const string& outputPath,
                          string& currentKey,
                          bool& hasKey)
{
    string error;
    bool ok = false;

    if (workMode == WorkMode::Encrypt)
    {
        if (!hasKey || currentKey.empty())
        {
            cout << "Ключ не был сгенерирован. Генерирую ключ автоматически..." << endl;
            generateKeyForSelectedAlgorithm(algorithm, outputPath, currentKey, hasKey);
        }

        cout << "Начинается шифрование..." << endl;

        ok = crypto::encryptFile(algorithm, sourceData, outputPath, currentKey, error);
        if (!ok)
        {
            cout << "Шифрование не выполнено: " << error << endl;
            return false;
        }

        cout << "Файл успешно зашифрован алгоритмом " << algoName(algorithm) << endl;
        cout << "Ключ для дешифрования: " << currentKey << endl;
        saveKeyToFile(outputPath, currentKey);
        return true;
    }

    if (!hasKey || currentKey.empty())
    {
        cout << "Для дешифрования нужен ключ." << endl;
        if (!readKeyOrKeyFile(currentKey, hasKey))
            return false;
    }

    cout << "Начинается дешифрование..." << endl;

    ok = crypto::decryptFile(algorithm, sourceData, outputPath, currentKey, error);
    if (!ok)
    {
        cout << "Дешифрование не выполнено: " << error << endl;
        return false;
    }

    cout << "Файл успешно дешифрован." << endl;
    return true;
}

bool performTextOperation(WorkMode workMode,
                          crypto::Algorithm algorithm,
                          const string& sourceData,
                          const string& outputPath,
                          string& currentKey,
                          bool& hasKey)
{
    string error;
    bool ok = false;
    string result;

    if (workMode == WorkMode::Encrypt)
    {
        if (!hasKey || currentKey.empty())
        {
            cout << "Ключ не был сгенерирован. Генерирую ключ автоматически..." << endl;
            generateKeyForSelectedAlgorithm(algorithm, outputPath, currentKey, hasKey);
        }

        cout << "Начинается шифрование текста..." << endl;

        ok = crypto::encryptText(algorithm, sourceData, currentKey, result, error);
        if (!ok)
        {
            cout << "Шифрование не выполнено: " << error << endl;
            return false;
        }

        cout << endl;
        cout << "Результат шифрования (HEX):" << endl;
        cout << result << endl;

        if (!outputPath.empty())
        {
            if (!crypto::writeTextFile(outputPath, result, error))
            {
                cout << "Не удалось сохранить результат в файл: " << error << endl;
                return false;
            }
            cout << "Результат дополнительно сохранён в файл: " << outputPath << endl;
        }

        cout << "Ключ для дешифрования: " << currentKey << endl;
        return true;
    }

    if (!hasKey || currentKey.empty())
    {
        cout << "Для дешифрования нужен ключ." << endl;
        if (!readKeyOrKeyFile(currentKey, hasKey))
            return false;
    }

    cout << "Введите HEX-шифротекст для дешифрования." << endl;

    ok = crypto::decryptText(algorithm, sourceData, currentKey, result, error);
    if (!ok)
    {
        cout << "Дешифрование не выполнено: " << error << endl;
        return false;
    }

    cout << endl;
    cout << "Результат дешифрования:" << endl;
    cout << result << endl;

    if (!outputPath.empty())
    {
        if (!crypto::writeTextFile(outputPath, result, error))
        {
            cout << "Не удалось сохранить результат в файл: " << error << endl;
            return false;
        }
        cout << "Результат дополнительно сохранён в файл: " << outputPath << endl;
    }

    return true;
}

} // namespace

int main()
{
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    DataMode dataMode = DataMode::None;
    bool hasDataMode = false;

    WorkMode workMode = WorkMode::None;
    bool hasWorkMode = false;

    crypto::Algorithm algorithm = crypto::Algorithm::AES;
    bool hasAlgorithm = false;

    string sourceData;
    bool hasSourceData = false;

    string outputPath;
    bool hasOutputPath = false;

    string currentKey;
    bool hasKey = false;

    while (true)
    {
        printMenu(dataMode, hasDataMode, workMode, hasWorkMode, algorithm, hasAlgorithm,
                  sourceData, hasSourceData, outputPath, hasOutputPath, hasKey, currentKey);

        int choice = 0;
        if (!askChoice("Выберите пункт меню:", 0, 7, choice))
        {
            cout << "Ввод завершён. Выход из программы." << endl;
            break;
        }

        switch (static_cast<MenuItem>(choice))
        {
            case MenuItem::Exit:
                cout << "Выход из программы." << endl;
                return 0;

            case MenuItem::SelectDataMode:
                if (chooseDataMode(dataMode, hasDataMode))
                {
                    hasSourceData = false;
                    hasOutputPath = false;
                    sourceData.clear();
                    outputPath.clear();
                }
                break;

            case MenuItem::SelectWorkMode:
                if (chooseWorkMode(workMode, hasWorkMode))
                {
                    // При смене режима сохраняем уже введенные данные, но ключ сбрасываем только при смене алгоритма
                }
                break;

            case MenuItem::SelectAlgorithm:
                if (chooseAlgorithm(algorithm, hasAlgorithm, currentKey, hasKey))
                {
                    // Новый алгоритм требует нового ключа
                }
                break;

            case MenuItem::InputSourceData:
                if (!hasDataMode)
                {
                    cout << "Сначала выберите тип данных." << endl;
                    break;
                }
                if (inputSourceData(dataMode, sourceData, hasSourceData))
                    cout << "Исходные данные сохранены." << endl;
                break;

            case MenuItem::InputOutputPath:
                if (!hasDataMode)
                {
                    cout << "Сначала выберите тип данных." << endl;
                    break;
                }
                if (inputOutputPath(dataMode, outputPath, hasOutputPath))
                    cout << "Параметр результата сохранён." << endl;
                break;

            case MenuItem::GenerateKey:
                if (!hasAlgorithm)
                {
                    cout << "Сначала выберите алгоритм." << endl;
                    break;
                }
                generateKeyForSelectedAlgorithm(algorithm, outputPath, currentKey, hasKey);
                break;

            case MenuItem::RunOperation:
                if (!hasDataMode)
                {
                    cout << "Сначала выберите тип данных." << endl;
                    break;
                }
                if (!hasWorkMode)
                {
                    cout << "Сначала выберите режим работы." << endl;
                    break;
                }
                if (!hasAlgorithm)
                {
                    cout << "Сначала выберите алгоритм." << endl;
                    break;
                }
                if (!hasSourceData)
                {
                    cout << "Сначала введите исходные данные." << endl;
                    break;
                }

                if (dataMode == DataMode::File && !hasOutputPath)
                {
                    cout << "Сначала укажите путь сохранения." << endl;
                    break;
                }

                if (dataMode == DataMode::Text)
                    performTextOperation(workMode, algorithm, sourceData, outputPath, currentKey, hasKey);
                else
                    performFileOperation(workMode, algorithm, sourceData, outputPath, currentKey, hasKey);

                cout << endl;
                break;
        }

        cout << endl;
    }

    return 0;
}
