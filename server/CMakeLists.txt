add_executable(server
    src/main.cpp
)

target_include_directories(server
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(server
    PRIVATE
        minidrive_shared
        minidrive_warnings
        pthread
)

target_compile_features(server PRIVATE cxx_std_23)

# Output to build root as ./build/server
set_target_properties(server PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)
