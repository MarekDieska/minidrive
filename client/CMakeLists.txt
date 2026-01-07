add_executable(client
    src/main.cpp
)

target_include_directories(client
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(client
    PRIVATE
        minidrive_shared
        minidrive_warnings
        pthread
)

target_compile_features(client PRIVATE cxx_std_23)

# Output to build root as ./build/client
set_target_properties(client PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)
