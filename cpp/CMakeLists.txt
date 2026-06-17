cmake_minimum_required(VERSION 3.16)
project(pkcs11_cpp_frontend CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

# ----- Demo executable -----
add_executable(demo demo.cpp)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "QNX")
    target_link_libraries(demo PRIVATE dl)
endif()

# ----- C++ test executable -----
add_executable(test_cpp test_cpp.cpp)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "QNX")
    target_link_libraries(test_cpp PRIVATE dl)
endif()

# Register as CTest test
enable_testing()
add_test(NAME cpp_unit_tests COMMAND test_cpp)
