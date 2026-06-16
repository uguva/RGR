#include "des_cipher.h"
#include "crypto_common.h"

#include <array>

using namespace std;

namespace crypto {
namespace {

constexpr size_t DES_BLOCK_SIZE = 8;
constexpr size_t DES_KEY_SIZE = 8;
constexpr uint8_t MAGIC[4] = {'R', 'G', 'Z', '1'};
constexpr uint8_t VERSION = 1;
constexpr uint8_t SALT_SIZE = 8;
constexpr uint8_t IV_SIZE = 8;

// Таблицы перестановок и расширения DES (классические)

const int IP[64] = {
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
};

const int FP[64] = {
    40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41,9,49,17,57,25
};

const int E[48] = {
    32,1,2,3,4,5,
    4,5,6,7,8,9,
    8,9,10,11,12,13,
    12,13,14,15,16,17,
    16,17,18,19,20,21,
    20,21,22,23,24,25,
    24,25,26,27,28,29,
    28,29,30,31,32,1
};

const int P[32] = {
    16,7,20,21,29,12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
};

const int PC1[56] = {
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
};

const int PC2[48] = {
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
};

const int SHIFTS[16] = {
    1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
};

// S-блоки DES (8 штук, каждый 4x16)
const int SBOX[8][4][16] = {
{   {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
    {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
    {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
    {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13} },
{   {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
    {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
    {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
    {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9} },
{   {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
    {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
    {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
    {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12} },
{   {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
    {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
    {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
    {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14} },
{   {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
    {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
    {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
    {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3} },
{   {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
    {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
    {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
    {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13} },
{   {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
    {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
    {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
    {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12} },
{   {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
    {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
    {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
    {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11} }
};

// Универсальная перестановка битов для 64-битного значения
uint64_t permute(uint64_t input, const int* table, int n, int inputBits)
{
    uint64_t output = 0;
    for (int i = 0; i < n; ++i)
    {
        output <<= 1;
        int bitPos = inputBits - table[i];
        output |= (input >> bitPos) & 1ULL;
    }
    return output;
}

uint32_t permute32(uint32_t input, const int* table, int n)
{
    return static_cast<uint32_t>(permute(static_cast<uint64_t>(input), table, n, 32));
}

// Преобразование 8 байт в uint64_t (big-endian, как в спецификации DES)
uint64_t bytesToU64(const uint8_t* data)
{
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i)
        value = (value << 8) | data[i];
    return value;
}

void u64ToBytes(uint64_t value, uint8_t* data)
{
    for (int i = 7; i >= 0; --i)
    {
        data[i] = static_cast<uint8_t>(value & 0xFF);
        value >>= 8;
    }
}

// Циклический сдвиг 28-битной половины ключа
uint32_t rotl28(uint32_t x, int n)
{
    return static_cast<uint32_t>(((x << n) | (x >> (28 - n))) & 0x0FFFFFFF);
}

// Функция Фейстеля: расширение, XOR с подключом, S-блоки, перестановка P
uint32_t feistel(uint32_t right, uint64_t subkey)
{
    uint64_t expanded = permute(static_cast<uint64_t>(right), E, 48, 32);
    expanded ^= subkey;

    uint32_t sOut = 0;
    for (int box = 0; box < 8; ++box)
    {
        uint8_t chunk = static_cast<uint8_t>((expanded >> (42 - 6 * box)) & 0x3F);
        int row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
        int col = (chunk >> 1) & 0x0F;
        sOut = static_cast<uint32_t>((sOut << 4) | SBOX[box][row][col]);
    }
    return permute32(sOut, P, 32);
}

// Генерация 16 раундовых подключей из 64-битного ключа (с отбрасыванием битов чётности)
array<uint64_t, 16> buildSubKeys(const vector<uint8_t>& key)
{
    array<uint64_t, 16> subkeys{};
    uint64_t key64 = bytesToU64(key.data());
    uint64_t perm56 = permute(key64, PC1, 56, 64);

    uint32_t c = static_cast<uint32_t>((perm56 >> 28) & 0x0FFFFFFF);
    uint32_t d = static_cast<uint32_t>(perm56 & 0x0FFFFFFF);

    for (int round = 0; round < 16; ++round)
    {
        c = rotl28(c, SHIFTS[round]);
        d = rotl28(d, SHIFTS[round]);
        uint64_t cd = (static_cast<uint64_t>(c) << 28) | d;
        subkeys[round] = permute(cd, PC2, 48, 56);
    }
    return subkeys;
}

// Обработка одного блока: IP, 16 раундов Фейстеля, FP
uint64_t processBlock(uint64_t block, const array<uint64_t, 16>& subkeys)
{
    block = permute(block, IP, 64, 64);
    uint32_t left = static_cast<uint32_t>(block >> 32);
    uint32_t right = static_cast<uint32_t>(block & 0xFFFFFFFFULL);

    for (int round = 0; round < 16; ++round)
    {
        uint32_t temp = right;
        right = left ^ feistel(right, subkeys[round]);
        left = temp;
    }

    uint64_t preOutput = (static_cast<uint64_t>(right) << 32) | left;
    return permute(preOutput, FP, 64, 64);
}

// Заголовок файла — аналогично AES, но с типом Algorithm::DES
void saveHeader(vector<uint8_t>& out, const vector<uint8_t>& salt, const vector<uint8_t>& iv)
{
    out.insert(out.end(), MAGIC, MAGIC + 4);
    out.push_back(VERSION);
    out.push_back(static_cast<uint8_t>(Algorithm::DES));
    out.push_back(SALT_SIZE);
    out.push_back(IV_SIZE);
    out.insert(out.end(), salt.begin(), salt.end());
    out.insert(out.end(), iv.begin(), iv.end());
}

bool readHeader(const vector<uint8_t>& in, size_t& offset, vector<uint8_t>& salt, vector<uint8_t>& iv, string& error)
{
    if (in.size() < 8)
    {
        error = "Файл слишком короткий: не найден заголовок.";
        return false;
    }
    if (in[0] != MAGIC[0] || in[1] != MAGIC[1] || in[2] != MAGIC[2] || in[3] != MAGIC[3])
    {
        error = "Это не файл, созданный данной программой.";
        return false;
    }
    if (in[4] != VERSION)
    {
        error = "Неподдерживаемая версия формата.";
        return false;
    }
    if (in[5] != static_cast<uint8_t>(Algorithm::DES))
    {
        error = "В файле указан не DES-алгоритм.";
        return false;
    }

    const size_t saltLen = in[6];
    const size_t ivLen = in[7];

    if (in.size() < 8 + saltLen + ivLen)
    {
        error = "Файл повреждён: не хватает данных salt/IV.";
        return false;
    }

    offset = 8;
    salt.assign(in.begin() + static_cast<ptrdiff_t>(offset), in.begin() + static_cast<ptrdiff_t>(offset + saltLen));
    offset += saltLen;
    iv.assign(in.begin() + static_cast<ptrdiff_t>(offset), in.begin() + static_cast<ptrdiff_t>(offset + ivLen));
    offset += ivLen;
    return true;
}

// PKCS#7 — те же функции, что в AES
void pkcs7Pad(vector<uint8_t>& data, size_t blockSize)
{
    size_t pad = blockSize - (data.size() % blockSize);
    if (pad == 0)
        pad = blockSize;
    data.insert(data.end(), pad, static_cast<uint8_t>(pad));
}

bool pkcs7Unpad(vector<uint8_t>& data, size_t blockSize, string& error)
{
    if (data.empty() || data.size() % blockSize != 0)
    {
        error = "Некорректная длина расшифрованных данных.";
        return false;
    }
    uint8_t pad = data.back();
    if (pad == 0 || pad > blockSize || pad > data.size())
    {
        error = "Неверная PKCS#7-подпись. Возможно, пароль неверный или файл повреждён.";
        return false;
    }
    for (size_t i = 0; i < pad; ++i)
    {
        if (data[data.size() - 1 - i] != pad)
        {
            error = "Неверная PKCS#7-подпись. Возможно, пароль неверный или файл повреждён.";
            return false;
        }
    }
    data.resize(data.size() - pad);
    return true;
}

} // namespace

// Шифрование файла DES, CBC, PKCS#7, заголовок
bool desEncryptFile(const string& inputPath,
                    const string& outputPath,
                    const string& password,
                    string& error)
{
    printStep("Чтение входного файла (DES)");
    vector<uint8_t> input;
    if (!readBinaryFile(inputPath, input, error))
        return false;

    printStep("Генерация salt и IV");
    vector<uint8_t> salt = makeRandomBytes(SALT_SIZE);
    vector<uint8_t> iv = makeRandomBytes(IV_SIZE);

    printStep("Формирование ключа");
    vector<uint8_t> key = deriveKey(password, salt, DES_KEY_SIZE);
    if (key.empty())
    {
        error = "Не удалось сформировать ключ. Проверьте пароль.";
        return false;
    }

    printStep("Добавление паддинга");
    pkcs7Pad(input, DES_BLOCK_SIZE);

    array<uint64_t, 16> subkeys = buildSubKeys(key);

    printStep("Шифрование блоков DES");
    vector<uint8_t> cipher;
    cipher.reserve(8 + salt.size() + iv.size() + input.size());
    saveHeader(cipher, salt, iv);

    array<uint8_t, DES_BLOCK_SIZE> prev{};
    for (size_t i = 0; i < iv.size(); ++i)
        prev[i] = iv[i];

    for (size_t offset = 0; offset < input.size(); offset += DES_BLOCK_SIZE)
    {
        array<uint8_t, DES_BLOCK_SIZE> block{};
        for (size_t i = 0; i < DES_BLOCK_SIZE; ++i)
            block[i] = input[offset + i];

        xorBuffer(block.data(), prev.data(), DES_BLOCK_SIZE);
        uint64_t block64 = bytesToU64(block.data());
        block64 = processBlock(block64, subkeys);
        u64ToBytes(block64, block.data());

        cipher.insert(cipher.end(), block.begin(), block.end());
        prev = block;
    }

    printStep("Запись результата");
    if (!writeBinaryFile(outputPath, cipher, error))
        return false;

    return true;
}

// Дешифрование DES: обратный порядок подключей (reverseSubkeys)
bool desDecryptFile(const string& inputPath,
                    const string& outputPath,
                    const string& password,
                    string& error)
{
    printStep("Чтение зашифрованного файла (DES)");
    vector<uint8_t> input;
    if (!readBinaryFile(inputPath, input, error))
        return false;

    vector<uint8_t> salt;
    vector<uint8_t> iv;
    size_t offset = 0;

    printStep("Проверка заголовка");
    if (!readHeader(input, offset, salt, iv, error))
        return false;

    if (iv.size() != DES_BLOCK_SIZE)
    {
        error = "Размер IV не совпадает с DES.";
        return false;
    }

    vector<uint8_t> data(input.begin() + static_cast<ptrdiff_t>(offset), input.end());
    if (data.empty() || data.size() % DES_BLOCK_SIZE != 0)
    {
        error = "Повреждённый файл: длина шифротекста должна быть кратна 8 байтам.";
        return false;
    }

    printStep("Формирование ключа");
    vector<uint8_t> key = deriveKey(password, salt, DES_KEY_SIZE);
    if (key.empty())
    {
        error = "Не удалось сформировать ключ. Проверьте пароль.";
        return false;
    }

    array<uint64_t, 16> subkeys = buildSubKeys(key);
    array<uint64_t, 16> reverseSubkeys{};
    for (size_t i = 0; i < subkeys.size(); ++i)
        reverseSubkeys[i] = subkeys[subkeys.size() - 1 - i]; // подключи в обратном порядке

    printStep("Дешифрование блоков DES");
    vector<uint8_t> plain;
    plain.reserve(data.size());

    array<uint8_t, DES_BLOCK_SIZE> prev{};
    for (size_t i = 0; i < iv.size(); ++i)
        prev[i] = iv[i];

    for (size_t pos = 0; pos < data.size(); pos += DES_BLOCK_SIZE)
    {
        array<uint8_t, DES_BLOCK_SIZE> block{};
        array<uint8_t, DES_BLOCK_SIZE> cipherBlock{};

        for (size_t i = 0; i < DES_BLOCK_SIZE; ++i)
        {
            block[i] = data[pos + i];
            cipherBlock[i] = data[pos + i];
        }

        uint64_t block64 = bytesToU64(block.data());
        block64 = processBlock(block64, reverseSubkeys);
        u64ToBytes(block64, block.data());

        xorBuffer(block.data(), prev.data(), DES_BLOCK_SIZE);
        plain.insert(plain.end(), block.begin(), block.end());
        prev = cipherBlock;
    }

    printStep("Удаление паддинга");
    if (!pkcs7Unpad(plain, DES_BLOCK_SIZE, error))
        return false;

    printStep("Запись результата");
    if (!writeBinaryFile(outputPath, plain, error))
        return false;

    return true;
}

} 