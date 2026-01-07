#include "server.hpp"
#include "minidrive/minidrive.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <cstdlib>
#include <iostream>
#include <string>

void print_usage(const char* program) {
    std::cerr << "Usage: " << program << " --port <PORT> --root <ROOT_PATH> [--verbose]\n"
              << "\n"
              << "Options:\n"
              << "  --port <PORT>       Port to listen on (default: $MINIDRIVE_PORT or 9000)\n"
              << "  --root <ROOT_PATH>  Root directory for file storage (required)\n"
              << "  --verbose           Enable verbose logging\n"
              << "  --help              Show this help message\n"
              << "\n"
              << "Environment variables:\n"
              << "  MINIDRIVE_PORT      Default port if --port not specified\n";
}

// Get environment variable with default value
std::string get_env(const char* name, const std::string& default_value = "") {
    const char* value = std::getenv(name);
    return value ? value : default_value;
}

int main(int argc, char* argv[]) {
    // Parse arguments
    minidrive::server::Server::Config config;
    bool has_port = false;
    bool has_root = false;
    bool verbose = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        }

        if (arg == "--port" && i + 1 < argc) {
            try {
                int port = std::stoi(argv[++i]);
                if (port < 1 || port > 65535) {
                    std::cerr << "Error: Port must be between 1 and 65535\n";
                    return 1;
                }
                config.port = static_cast<std::uint16_t>(port);
                has_port = true;
            } catch (const std::exception&) {
                std::cerr << "Error: Invalid port number\n";
                return 1;
            }
            continue;
        }

        if (arg == "--root" && i + 1 < argc) {
            config.root_path = argv[++i];
            has_root = true;
            continue;
        }

        if (arg == "--verbose" || arg == "-v") {
            verbose = true;
            continue;
        }

        std::cerr << "Error: Unknown argument: " << arg << "\n";
        print_usage(argv[0]);
        return 1;
    }

    // Use environment variables as fallback
    if (!has_port) {
        std::string env_port = get_env("MINIDRIVE_PORT", "9000");
        try {
            int port = std::stoi(env_port);
            if (port >= 1 && port <= 65535) {
                config.port = static_cast<std::uint16_t>(port);
                has_port = true;
            }
        } catch (...) {}
    }

    if (!has_root) {
        std::cerr << "Error: --root is required\n";
        print_usage(argv[0]);
        return 1;
    }

    // Setup logging
    try {
        auto console = spdlog::stdout_color_mt("console");
        spdlog::set_default_logger(console);

        if (verbose) {
            spdlog::set_level(spdlog::level::debug);
        } else {
            spdlog::set_level(spdlog::level::info);
        }

        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
    } catch (const spdlog::spdlog_ex& ex) {
        std::cerr << "Logger initialization failed: " << ex.what() << "\n";
        return 1;
    }

    spdlog::info("MiniDrive Server v{}", minidrive::version());
    spdlog::info("Starting server on port {} with root {}", config.port, config.root_path.string());

    // Create and start server
    minidrive::server::Server server(config);

    if (!server.start()) {
        spdlog::error("Failed to start server");
        return 1;
    }

    return 0;
}
