cmake_minimum_required(VERSION 3.22)
project(minidrive VERSION 0.1.0 LANGUAGES CXX)

# C++23 standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile_commands.json for IDE
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Load dependencies
include(cmake/Dependencies.cmake)

# Subprojects
add_subdirectory(shared)
add_subdirectory(server)
add_subdirectory(client)

# Tests (optional)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
    enable_testing()
    add_subdirectory(tests)
endif()
