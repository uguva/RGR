cmake_minimum_required(VERSION 3.10)
project(AsymmetricCryptoRGR)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Указываем пути к заголовкам
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Собираем модули шифрования (CMake автоматически выберет .so на Linux или .dll на Windows)
add_library(rsa SHARED modules/rsa/rsa_module.cpp)
target_link_libraries(rsa gmp) # Связываем с библиотекой GMP

add_library(dh SHARED modules/dh/dh_module.cpp)
target_link_libraries(dh gmp) # Связываем с библиотекой GMP

# Собираем основное управляющее приложение
add_executable(crypto_app src/main.cpp src/module_manager.cpp src/ui_utils.cpp)

if(WIN32)
    # В Windows функции dlopen встроенны по умолчанию
else()
    target_link_libraries(crypto_app dl) # В Linux подключаем dlfcn
endif()

# Кроссплатформенный перенос собранных плагинов в рабочую папку бинарников
add_custom_command(TARGET rsa POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/plugins/rsa
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:rsa> ${CMAKE_BINARY_DIR}/plugins/rsa/
)

add_custom_command(TARGET dh POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/plugins/DiffieHellman
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:dh> ${CMAKE_BINARY_DIR}/plugins/DiffieHellman/
)
