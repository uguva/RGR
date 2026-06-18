cmake_minimum_required(VERSION 3.10)
project(rgr_crypto_modules)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_library(trithemius SHARED trithemius_module.cpp)
add_library(blowfish SHARED blowfish_module.cpp)

add_executable(crypto_app main.cpp module_manager.cpp)

target_link_libraries(blowfish PRIVATE OpenSSL::Crypto)
target_link_libraries(crypto_app PRIVATE dl)

set_target_properties(trithemius PROPERTIES OUTPUT_NAME "trithemius")
set_target_properties(blowfish PROPERTIES OUTPUT_NAME "blowfish")
