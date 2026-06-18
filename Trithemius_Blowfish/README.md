# Модуль РГР: Тритемий и Blowfish

В проекте есть `login()`, `enum class`, динамическая загрузка модулей и два шифра.

Файлы:
- `main.cpp` — вход в программу, `login()`, меню, `enum class`, работа с текстом и файлами.
- `module_manager.h / module_manager.cpp` — загрузка `.so` через `dlopen`, `dlsym`, `dlclose`.
- `trithemius_module.cpp` — шифр Тритемия.
- `blowfish_module.cpp` — Blowfish через OpenSSL.
- `encryption_interface.h` — общий интерфейс модулей.
- `CMakeLists.txt` — сборка проекта.

Сборка на Ubuntu:

```bash
sudo apt install cmake g++ libssl-dev
mkdir build
cd build
cmake ..
make
./crypto_app
```

Пароль для входа:

```text
456654
```

Для файлов нужно указывать расширение, например `input.txt`. При шифровании создается файл `input.txt.enc`. При расшифровке `.enc` убирается автоматически.
