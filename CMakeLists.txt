cmake_minimum_required(VERSION 3.10)
project(AsymmetricCryptoRGR)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Автоматическое определение расширения динамических библиотек
if(WIN32)
    set(LIB_EXT ".dll")
else()
    set(LIB_EXT ".so")
endif()

# Указываем пути к локальным заголовочным файлам проекта
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# === НАСТРОЙКА GMP ДЛЯ WINDOWS (MinGW / MSYS2 ucrt64) ===
if(WIN32)
    # Явно указываем CMake, где искать заголовочные файлы и линковать libgmp
    include_directories(C:/msys64/ucrt64/include)
    link_directories(C:/msys64/ucrt64/lib)
endif()

# === СБОРКА ПЛАГИНОВ ===

# Модуль RSA
add_library(rsa SHARED modules/rsa/rsa_module.cpp)
target_link_libraries(rsa gmp)

# Модуль Diffie-Hellman
add_library(dh SHARED modules/dh/dh_module.cpp)
target_link_libraries(dh gmp)

# Модуль AES
add_library(aes SHARED modules/aes/aes_module.cpp)

# Модуль DES
add_library(des SHARED modules/des/des_module.cpp)

# Модуль Аффинного шифра
add_library(affine SHARED modules/affine/affine_module.cpp)

# Модуль Шифра Вернама
add_library(vernam SHARED modules/vernam/vernam_module.cpp)

# Модуль Тритемиуса
add_library(trithemius SHARED modules/trithemius/trithemius_module.cpp)

# Модуль Blowfish (требует OpenSSL)
add_library(blowfish SHARED modules/blowfish/blowfish_module.cpp)
target_link_libraries(blowfish crypto)

# === СБОРКА ОСНОВНОГО ПРИЛОЖЕНИЯ ===
add_executable(crypto_app src/main.cpp src/module_manager.cpp src/ui_utils.cpp)

if(WIN32)
    # В Windows функции динамической загрузки (LoadLibrary) встроены по умолчанию
else()
    target_link_libraries(crypto_app ${CMAKE_DL_LIBS}) # Для Linux подключаем dlfcn
endif()


# === МАКРОС АВТОМАТИЧЕСКОГО КОПИРОВАНИЯ В ПАПКУ BUILD ===
macro(copy_plugin_target TARGET_NAME DIR_NAME)
    add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/plugins/${DIR_NAME}
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${TARGET_NAME}> ${CMAKE_BINARY_DIR}/plugins/${DIR_NAME}/lib${TARGET_NAME}${LIB_EXT}
    )
endmacro()

copy_plugin_target(rsa rsa)
copy_plugin_target(dh DiffieHellman)
copy_plugin_target(aes aes)
copy_plugin_target(des des)
copy_plugin_target(affine affine)
copy_plugin_target(vernam vernam)
copy_plugin_target(trithemius trithemius)
copy_plugin_target(blowfish blowfish)
