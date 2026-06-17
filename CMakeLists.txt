cmake_minimum_required(VERSION 3.10)
project(AsymmetricCryptoRGR)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Указываем пути к заголовкам
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Собираем библиотеки
add_library(rsa SHARED modules/rsa/rsa_module.cpp)
add_library(dh SHARED modules/dh/dh_module.cpp)

# Собираем приложение
add_executable(crypto_app src/main.cpp src/module_manager.cpp)
target_link_libraries(crypto_app dl)

# Исправленные команды копирования (без SHARED)
add_custom_command(TARGET rsa POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/plugins/rsa
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:rsa> ${CMAKE_BINARY_DIR}/plugins/rsa/librsa.so
)

add_custom_command(TARGET dh POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/plugins/DiffieHellman
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:dh> ${CMAKE_BINARY_DIR}/plugins/DiffieHellman/libdh.so
)
