cmake_minimum_required(VERSION 3.10)
project(AsymmetricCryptoRGR)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Кроссплатформенное определение расширения динамических библиотек
if(WIN32)
    set(LIB_EXT ".dll")
else()
    set(LIB_EXT ".so")
endif()

# Определение плагинов
add_library(rsa SHARED modules/rsa/rsa_module.cpp)
target_link_libraries(rsa gmp)

add_library(dh SHARED modules/dh/dh_module.cpp)
target_link_libraries(dh gmp)

add_library(aes SHARED modules/aes/aes_module.cpp)
add_library(des SHARED modules/des/des_module.cpp)

add_library(affine SHARED modules/affine/affine_module.cpp)
add_library(vernam SHARED modules/vernam/vernam_module.cpp)

# Сборка исполняемого файла
add_executable(crypto_app src/main.cpp src/module_manager.cpp src/ui_utils.cpp)

if(WIN32)
    # Windows native dlfcn loader API handles dependency linking
else()
    target_link_libraries(crypto_app dl)
endif()

# Макрос для унифицированного копирования плагинов
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
