#include "aes_cipher.h"
#include "crypto_common.h"

#include <array>

using namespace std;

namespace crypto {
namespace {

// Параметры AES-128
constexpr size_t AES_BLOCK_SIZE = 16;
constexpr size_t AES_KEY_SIZE = 16;
constexpr size_t AES_ROUNDS = 10;

// Сигнатура и версия формата файла
constexpr uint8_t MAGIC[4] = {'R', 'G', 'Z', '1'};
constexpr uint8_t VERSION = 1;
constexpr uint8_t SALT_SIZE = 16;
constexpr uint8_t IV_SIZE = 16;

// Умножение в поле GF(2^8) с неприводимым полиномом x^8 + x^4 + x^3 + x + 1
uint8_t xtime(uint8_t x)
{
    return static_cast<uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
}

uint8_t gfMul(uint8_t a, uint8_t b)
{
    uint8_t result = 0;
    while (b)
    {
        if (b & 1)
            result ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return result;
}

// Возведение в степень в GF(2^8) — для построения S-Box
uint8_t gfPow(uint8_t a, int e)
{
    uint8_t result = 1;
    while (e > 0)
    {
        if (e & 1)
            result = gfMul(result, a);
        a = gfMul(a, a);
        e >>= 1;
    }
    return result;
}

// Циклический сдвиг байта влево
uint8_t rotl8(uint8_t x, unsigned int n)
{
    n &= 7U;
    if (n == 0)
        return x;
    return static_cast<uint8_t>((x << n) | (x >> (8U - n)));
}

// Генерация S-Box (алгоритм из спецификации AES)
uint8_t aesSBox(uint8_t x)
{
    uint8_t inv = (x == 0) ? 0 : gfPow(x, 254);
    return static_cast<uint8_t>(inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63);
}

// Обратный S-Box — через таблицу, заполняемую один раз при первом вызове
uint8_t aesInvSBox(uint8_t x)
{
    static array<uint8_t, 256> invTable{};
    static bool initialized = false;

    if (!initialized)
    {
        for (int i = 0; i < 256; ++i)
        {
            invTable[aesSBox(static_cast<uint8_t>(i))] = static_cast<uint8_t>(i);
        }
        initialized = true;
    }
    return invTable[x];
}

// Раундовая константа (Rcon) для расширения ключа
uint8_t rconValue(size_t round)
{
    uint8_t c = 1;
    for (size_t i = 1; i < round; ++i)
        c = gfMul(c, 2);
    return c;
}

// SubBytes — замена каждого байта по S-Box
void subBytes(array<uint8_t, 16>& state)
{
    for (auto& b : state)
        b = aesSBox(b);
}

void invSubBytes(array<uint8_t, 16>& state)
{
    for (auto& b : state)
        b = aesInvSBox(b);
}

// ShiftRows — циклический сдвиг строк матрицы состояния
void shiftRows(array<uint8_t, 16>& state)
{
    array<uint8_t, 16> t = state;
    state[0]  = t[0];
    state[1]  = t[5];
    state[2]  = t[10];
    state[3]  = t[15];

    state[4]  = t[4];
    state[5]  = t[9];
    state[6]  = t[14];
    state[7]  = t[3];

    state[8]  = t[8];
    state[9]  = t[13];
    state[10] = t[2];
    state[11] = t[7];

    state[12] = t[12];
    state[13] = t[1];
    state[14] = t[6];
    state[15] = t[11];
}

void invShiftRows(array<uint8_t, 16>& state)
{
    array<uint8_t, 16> t = state;
    state[0]  = t[0];
    state[1]  = t[13];
    state[2]  = t[10];
    state[3]  = t[7];

    state[4]  = t[4];
    state[5]  = t[1];
    state[6]  = t[14];
    state[7]  = t[11];

    state[8]  = t[8];
    state[9]  = t[5];
    state[10] = t[2];
    state[11] = t[15];

    state[12] = t[12];
    state[13] = t[9];
    state[14] = t[6];
    state[15] = t[3];
}

// MixColumns — умножение каждого столбца на фиксированную матрицу в GF(2^8)
void mixColumns(array<uint8_t, 16>& state)
{
    for (int c = 0; c < 4; ++c)
    {
        uint8_t a0 = state[c * 4 + 0];
        uint8_t a1 = state[c * 4 + 1];
        uint8_t a2 = state[c * 4 + 2];
        uint8_t a3 = state[c * 4 + 3];

        state[c * 4 + 0] = static_cast<uint8_t>(gfMul(a0, 2) ^ gfMul(a1, 3) ^ a2 ^ a3);
        state[c * 4 + 1] = static_cast<uint8_t>(a0 ^ gfMul(a1, 2) ^ gfMul(a2, 3) ^ a3);
        state[c * 4 + 2] = static_cast<uint8_t>(a0 ^ a1 ^ gfMul(a2, 2) ^ gfMul(a3, 3));
        state[c * 4 + 3] = static_cast<uint8_t>(gfMul(a0, 3) ^ a1 ^ a2 ^ gfMul(a3, 2));
    }
}

void invMixColumns(array<uint8_t, 16>& state)
{
    for (int c = 0; c < 4; ++c)
    {
        uint8_t a0 = state[c * 4 + 0];
        uint8_t a1 = state[c * 4 + 1];
        uint8_t a2 = state[c * 4 + 2];
        uint8_t a3 = state[c * 4 + 3];

        state[c * 4 + 0] = static_cast<uint8_t>(gfMul(a0, 14) ^ gfMul(a1, 11) ^ gfMul(a2, 13) ^ gfMul(a3, 9));
        state[c * 4 + 1] = static_cast<uint8_t>(gfMul(a0, 9)  ^ gfMul(a1, 14) ^ gfMul(a2, 11) ^ gfMul(a3, 13));
        state[c * 4 + 2] = static_cast<uint8_t>(gfMul(a0, 13) ^ gfMul(a1, 9)  ^ gfMul(a2, 14) ^ gfMul(a3, 11));
        state[c * 4 + 3] = static_cast<uint8_t>(gfMul(a0, 11) ^ gfMul(a1, 13) ^ gfMul(a2, 9)  ^ gfMul(a3, 14));
    }
}

// Наложение раундового ключа (XOR)
void addRoundKey(array<uint8_t, 16>& state, const array<uint8_t, 176>& roundKeys, size_t round)
{
    for (size_t i = 0; i < AES_BLOCK_SIZE; ++i)
        state[i] ^= roundKeys[round * AES_BLOCK_SIZE + i];
}

// Алгоритм расширения ключа (Key Expansion) для AES-128
array<uint8_t, 176> expandKey(const vector<uint8_t>& key)
{
    array<uint8_t, 176> roundKeys{};
    for (size_t i = 0; i < AES_KEY_SIZE; ++i)
        roundKeys[i] = key[i];

    size_t bytesGenerated = AES_KEY_SIZE;
    size_t rconIteration = 1;
    uint8_t temp[4];

    while (bytesGenerated < roundKeys.size())
    {
        for (size_t i = 0; i < 4; ++i)
            temp[i] = roundKeys[bytesGenerated - 4 + i];

        // Каждые 16 байт (длина ключа) — применение g-функции
        if (bytesGenerated % AES_KEY_SIZE == 0)
        {
            // RotWord
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            // SubWord
            for (auto& b : temp)
                b = aesSBox(b);
            // XOR с Rcon
            temp[0] ^= rconValue(rconIteration++);
        }

        for (size_t i = 0; i < 4; ++i)
        {
            roundKeys[bytesGenerated] = static_cast<uint8_t>(roundKeys[bytesGenerated - AES_KEY_SIZE] ^ temp[i]);
            ++bytesGenerated;
        }
    }
    return roundKeys;
}

// Шифрование одного блока (16 байт)
array<uint8_t, 16> encryptBlock(array<uint8_t, 16> block, const array<uint8_t, 176>& roundKeys)
{
    addRoundKey(block, roundKeys, 0);

    for (size_t round = 1; round < AES_ROUNDS; ++round)
    {
        subBytes(block);
        shiftRows(block);
        mixColumns(block);
        addRoundKey(block, roundKeys, round);
    }

    subBytes(block);
    shiftRows(block);
    addRoundKey(block, roundKeys, AES_ROUNDS);
    return block;
}

// Дешифрование блока — обратный порядок операций с обратными преобразованиями
array<uint8_t, 16> decryptBlock(array<uint8_t, 16> block, const array<uint8_t, 176>& roundKeys)
{
    addRoundKey(block, roundKeys, AES_ROUNDS);

    for (int round = static_cast<int>(AES_ROUNDS) - 1; round >= 1; --round)
    {
        invShiftRows(block);
        invSubBytes(block);
        addRoundKey(block, roundKeys, static_cast<size_t>(round));
        invMixColumns(block);
    }

    invShiftRows(block);
    invSubBytes(block);
    addRoundKey(block, roundKeys, 0);
    return block;
}

// Формирование заголовка: магия, версия, тип алгоритма, длины соли и IV, сами соль и IV
void saveHeader(vector<uint8_t>& out, const vector<uint8_t>& salt, const vector<uint8_t>& iv)
{
    out.insert(out.end(), MAGIC, MAGIC + 4);
    out.push_back(VERSION);
    out.push_back(static_cast<uint8_t>(Algorithm::AES));
    out.push_back(SALT_SIZE);
    out.push_back(IV_SIZE);
    out.insert(out.end(), salt.begin(), salt.end());
    out.insert(out.end(), iv.begin(), iv.end());
}

// Чтение заголовка, извлечение соли и IV, проверка целостности
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

    if (in[5] != static_cast<uint8_t>(Algorithm::AES))
    {
        error = "В файле указан не AES-алгоритм.";
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

// Добавление PKCS#7 паддинга
void pkcs7Pad(vector<uint8_t>& data, size_t blockSize)
{
    size_t pad = blockSize - (data.size() % blockSize);
    if (pad == 0)
        pad = blockSize;
    data.insert(data.end(), pad, static_cast<uint8_t>(pad));
}

// Удаление PKCS#7 паддинга с проверкой корректности
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

// Шифрование файла: читаем, генерируем соль/IV, ключ из пароля, CBC, запись с заголовком
bool aesEncryptFile(const string& inputPath,
                    const string& outputPath,
                    const string& password,
                    string& error)
{
    printStep("Чтение входного файла (AES)");
    vector<uint8_t> input;
    if (!readBinaryFile(inputPath, input, error))
        return false;

    printStep("Генерация salt и IV");
    vector<uint8_t> salt = makeRandomBytes(SALT_SIZE);
    vector<uint8_t> iv = makeRandomBytes(IV_SIZE);

    printStep("Формирование ключа");
    vector<uint8_t> key = deriveKey(password, salt, AES_KEY_SIZE);
    if (key.empty())
    {
        error = "Не удалось сформировать ключ. Проверьте пароль.";
        return false;
    }

    printStep("Добавление паддинга");
    pkcs7Pad(input, AES_BLOCK_SIZE);

    array<uint8_t, 176> roundKeys = expandKey(key);

    printStep("Шифрование блоков AES");
    vector<uint8_t> cipher;
    cipher.reserve(8 + salt.size() + iv.size() + input.size());
    saveHeader(cipher, salt, iv);

    // CBC: prev хранит предыдущий блок шифротекста (или IV для первого блока)
    array<uint8_t, AES_BLOCK_SIZE> prev{};
    for (size_t i = 0; i < iv.size(); ++i)
        prev[i] = iv[i];

    for (size_t offset = 0; offset < input.size(); offset += AES_BLOCK_SIZE)
    {
        array<uint8_t, AES_BLOCK_SIZE> block{};
        for (size_t i = 0; i < AES_BLOCK_SIZE; ++i)
            block[i] = input[offset + i];

        xorBuffer(block.data(), prev.data(), AES_BLOCK_SIZE);
        block = encryptBlock(block, roundKeys);
        cipher.insert(cipher.end(), block.begin(), block.end());
        prev = block;
    }

    printStep("Запись результата");
    if (!writeBinaryFile(outputPath, cipher, error))
        return false;

    return true;
}

// Дешифрование файла: проверка заголовка, извлечение соли/IV, восстановление ключа, CBC, удаление паддинга
bool aesDecryptFile(const string& inputPath,
                    const string& outputPath,
                    const string& password,
                    string& error)
{
    printStep("Чтение зашифрованного файла (AES)");
    vector<uint8_t> input;
    if (!readBinaryFile(inputPath, input, error))
        return false;

    vector<uint8_t> salt;
    vector<uint8_t> iv;
    size_t offset = 0;

    printStep("Проверка заголовка");
    if (!readHeader(input, offset, salt, iv, error))
        return false;

    if (iv.size() != AES_BLOCK_SIZE)
    {
        error = "Размер IV не совпадает с AES.";
        return false;
    }

    vector<uint8_t> data(input.begin() + static_cast<ptrdiff_t>(offset), input.end());
    if (data.empty() || data.size() % AES_BLOCK_SIZE != 0)
    {
        error = "Повреждённый файл: длина шифротекста должна быть кратна 16 байтам.";
        return false;
    }

    printStep("Формирование ключа");
    vector<uint8_t> key = deriveKey(password, salt, AES_KEY_SIZE);
    if (key.empty())
    {
        error = "Не удалось сформировать ключ. Проверьте пароль.";
        return false;
    }

    array<uint8_t, 176> roundKeys = expandKey(key);

    printStep("Дешифрование блоков AES");
    vector<uint8_t> plain;
    plain.reserve(data.size());

    array<uint8_t, AES_BLOCK_SIZE> prev{};
    for (size_t i = 0; i < iv.size(); ++i)
        prev[i] = iv[i];

    for (size_t pos = 0; pos < data.size(); pos += AES_BLOCK_SIZE)
    {
        array<uint8_t, AES_BLOCK_SIZE> block{};
        array<uint8_t, AES_BLOCK_SIZE> cipherBlock{}; // запоминаем шифротекст для следующей итерации

        for (size_t i = 0; i < AES_BLOCK_SIZE; ++i)
        {
            block[i] = data[pos + i];
            cipherBlock[i] = data[pos + i];
        }

        block = decryptBlock(block, roundKeys);
        xorBuffer(block.data(), prev.data(), AES_BLOCK_SIZE);

        plain.insert(plain.end(), block.begin(), block.end());
        prev = cipherBlock;
    }

    printStep("Удаление паддинга");
    if (!pkcs7Unpad(plain, AES_BLOCK_SIZE, error))
        return false;

    printStep("Запись результата");
    if (!writeBinaryFile(outputPath, plain, error))
        return false;

    return true;
}

} 