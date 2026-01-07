add_library(minidrive_shared STATIC
    src/version.cpp
)

target_include_directories(minidrive_shared
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(minidrive_shared
    PUBLIC
        nlohmann_json::nlohmann_json
        spdlog::spdlog
        sodium
    PUBLIC
        minidrive_warnings
)

# Require C++23
target_compile_features(minidrive_shared PUBLIC cxx_std_23)

set_target_properties(minidrive_shared PROPERTIES EXPORT_NAME shared)
