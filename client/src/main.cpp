#include "client.hpp"
#include "commands.hpp"
#include "minidrive/minidrive.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>

#include <csignal>
#include <iostream>
#include <string>
#include <termios.h>
#include <unistd.h>

namespace {

// Secure password reading (no echo)
std::string read_password(const std::string& prompt) {
    std::cout << prompt << std::flush;
    
    // Save current terminal settings
    termios old_settings{};
    tcgetattr(STDIN_FILENO, &old_settings);
    
    // Disable echo
    termios new_settings = old_settings;
    new_settings.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_settings);
    
    // Read password
    std::string password;
    std::getline(std::cin, password);
    
    // Restore settings
    tcsetattr(STDIN_FILENO, TCSANOW, &old_settings);
    
    // New line (since echo was disabled)
    std::cout << "\n";
    
    return password;
}

// Global pointer to client for signal handler
minidrive::client::Client* g_client = nullptr;

void signal_handler(int signal) {
    if (signal == SIGINT) {
        std::cout << "\n";
        if (g_client) {
            g_client->disconnect();
        }
        std::exit(0);
    }
}

// Get environment variable with default value
std::string get_env(const char* name, const std::string& default_value = "") {
    const char* value = std::getenv(name);
    return value ? value : default_value;
}

void print_usage(const char* program) {
    std::cerr << "Usage: " << program << " [username@]<host>:<port> [--log <log_file>]\n"
              << "\n"
              << "Examples:\n"
              << "  " << program << " 127.0.0.1:9000           # Public mode\n"
              << "  " << program << " alice@127.0.0.1:9000     # Authenticated mode\n"
              << "  " << program << " 127.0.0.1:9000 --log client.log\n"
              << "\n"
              << "Environment variables:\n"
              << "  MINIDRIVE_HOST      Default host (default: 127.0.0.1)\n"
              << "  MINIDRIVE_PORT      Default port (default: 9000)\n"
              << "  MINIDRIVE_USERNAME  Default username for authentication\n";
}

// Parse endpoint (user@host:port or host:port)
struct Endpoint {
    std::optional<std::string> username;
    std::string host;
    std::uint16_t port;
};

std::optional<Endpoint> parse_endpoint(const std::string& str) {
    Endpoint ep;

    std::string remaining = str;

    // Look for @
    auto at_pos = remaining.find('@');
    if (at_pos != std::string::npos) {
        ep.username = remaining.substr(0, at_pos);
        remaining = remaining.substr(at_pos + 1);
    }

    // Look for :
    auto colon_pos = remaining.rfind(':');
    if (colon_pos == std::string::npos) {
        return std::nullopt;
    }

    ep.host = remaining.substr(0, colon_pos);
    std::string port_str = remaining.substr(colon_pos + 1);

    if (ep.host.empty() || port_str.empty()) {
        return std::nullopt;
    }

    try {
        int port = std::stoi(port_str);
        if (port < 1 || port > 65535) {
            return std::nullopt;
        }
        ep.port = static_cast<std::uint16_t>(port);
    } catch (...) {
        return std::nullopt;
    }

    return ep;
}

// Format file size
std::string format_size(std::uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_idx = 0;
    double size = static_cast<double>(bytes);

    while (size >= 1024.0 && unit_idx < 4) {
        size /= 1024.0;
        ++unit_idx;
    }

    std::ostringstream oss;
    if (unit_idx == 0) {
        oss << bytes << " " << units[unit_idx];
    } else {
        oss << std::fixed << std::setprecision(1) << size << " " << units[unit_idx];
    }
    return oss.str();
}

// Print response
void print_response(const minidrive::Response& resp) {
    if (resp.is_ok()) {
        std::cout << "OK\n";

        // Print files
        if (resp.files) {
            for (const auto& file : *resp.files) {
                if (file.is_directory) {
                    std::cout << "  [DIR]  " << file.name << "/\n";
                } else {
                    std::cout << "  [FILE] " << file.name
                              << " (" << format_size(file.size) << ")\n";
                }
            }
            std::cout << "Total: " << resp.files->size() << " items\n";
        }

        // Current path
        if (resp.current_path && !resp.files) {
            std::cout << "Current directory: " << *resp.current_path << "\n";
        }
    } else {
        std::cout << "ERROR: " << resp.code << "\n";
        std::cout << resp.message << "\n";
    }
}

// Progress bar
void print_progress(std::uint64_t current, std::uint64_t total) {
    int percentage = static_cast<int>((current * 100) / total);
    int bar_width = 40;
    int filled = (bar_width * percentage) / 100;

    std::cout << "\r[";
    for (int i = 0; i < bar_width; ++i) {
        if (i < filled) {
            std::cout << "=";
        } else if (i == filled) {
            std::cout << ">";
        } else {
            std::cout << " ";
        }
    }
    std::cout << "] " << percentage << "% "
              << format_size(current) << "/" << format_size(total)
              << std::flush;

    if (current >= total) {
        std::cout << "\n";
    }
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    // Get defaults from environment
    std::string default_host = get_env("MINIDRIVE_HOST", "127.0.0.1");
    std::string default_port = get_env("MINIDRIVE_PORT", "9000");
    std::string default_username = get_env("MINIDRIVE_USERNAME", "");

    // Parse arguments
    std::optional<std::string> log_file;
    std::optional<Endpoint> endpoint;

    // Parse optional arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--log" && i + 1 < argc) {
            log_file = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg[0] != '-') {
            endpoint = parse_endpoint(arg);
        }
    }

    // Use environment variables if no endpoint provided
    if (!endpoint) {
        Endpoint ep;
        ep.host = default_host;
        try {
            ep.port = static_cast<std::uint16_t>(std::stoi(default_port));
        } catch (...) {
            ep.port = 9000;
        }
        if (!default_username.empty()) {
            ep.username = default_username;
        }
        endpoint = ep;
    }

    // Setup logging
    try {
        if (log_file) {
            auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(*log_file, true);
            auto logger = std::make_shared<spdlog::logger>("client", file_sink);
            spdlog::set_default_logger(logger);
        } else {
            spdlog::set_level(spdlog::level::off);
        }
    } catch (const spdlog::spdlog_ex& ex) {
        std::cerr << "Logger initialization failed: " << ex.what() << "\n";
    }

    std::cout << "MiniDrive client (version " << minidrive::version() << ")\n";

    // Create client
    minidrive::client::Client::Config config;
    config.host = endpoint->host;
    config.port = endpoint->port;
    config.username = endpoint->username;
    config.log_file = log_file;

    minidrive::client::Client client(config);
    g_client = &client;

    // Set signal handler
    std::signal(SIGINT, signal_handler);

    // Connect
    std::cout << "Connecting to " << config.host << ":" << config.port << "...\n";

    if (!client.connect()) {
        std::cerr << "Error: " << client.last_error() << "\n";
        return 1;
    }

    // Authentication
    if (!config.username) {
        // Public mode
        std::cout << "[warning] operating in public mode - files are visible to everyone\n";
    } else {
        // Authenticated mode
        std::string username = *config.username;
        
        // Check if user exists
        bool exists = client.user_exists(username);
        
        if (!exists) {
            // Užívateľ neexistuje - ponúkneme registráciu
            std::cout << "User " << username << " not found. Register? (y/n): ";
            std::string answer;
            std::getline(std::cin, answer);
            
            if (answer.empty() || (answer[0] != 'y' && answer[0] != 'Y')) {
                std::cout << "Registration cancelled.\n";
                client.disconnect();
                return 0;
            }
            
            // Získame heslo (bez echo)
            std::string password = read_password("Password: ");
            
            if (password.length() < 4) {
                std::cerr << "Error: Password too short (min 4 chars)\n";
                client.disconnect();
                return 1;
            }
            
            // Registrácia
            auto reg_resp = client.register_user(username, password);
            if (!reg_resp.is_ok()) {
                std::cerr << "Registration failed: " << reg_resp.message << "\n";
                client.disconnect();
                return 1;
            }
            
            std::cout << "User registered successfully.\n";
            
            // Teraz sa prihlásime
            auto auth_resp = client.authenticate(username, password);
            if (!auth_resp.is_ok()) {
                std::cerr << "Authentication failed: " << auth_resp.message << "\n";
                client.disconnect();
                return 1;
            }
            
            std::cout << "Logged as " << username << "\n";
        } else {
            // Užívateľ existuje - prihlásime sa
            std::string password = read_password("Password: ");
            
            auto auth_resp = client.authenticate(username, password);
            if (!auth_resp.is_ok()) {
                std::cerr << "Authentication failed: " << auth_resp.message << "\n";
                client.disconnect();
                return 1;
            }
            
            std::cout << "Logged as " << username << "\n";
        }

        // Kontrola nedokončených uploadov
        auto pending = client.get_pending_uploads();
        if (!pending.empty()) {
            std::cout << "Incomplete upload/downloads detected, resume? (y/n): ";
            std::string answer;
            std::getline(std::cin, answer);
            
            if (!answer.empty() && (answer[0] == 'y' || answer[0] == 'Y')) {
                for (const auto& p : pending) {
                    std::cout << "UPLOAD " << p.remote_path << " (resuming from " 
                              << p.bytes_uploaded << "/" << p.total_size << " bytes)\n";
                    
                    // Potrebujeme lokálnu cestu - user ju musí zadať
                    std::cout << "Enter local path for " << p.remote_path << " (or skip): ";
                    std::string local_path;
                    std::getline(std::cin, local_path);
                    
                    if (local_path.empty() || local_path == "skip") {
                        std::cout << "Skipped.\n";
                        continue;
                    }
                    
                    auto resp = client.resume_upload(local_path, p.remote_path, 
                                                     p.bytes_uploaded, print_progress);
                    if (resp.is_ok()) {
                        std::cout << "OK\n";
                    } else {
                        std::cout << "ERROR: " << resp.message << "\n";
                    }
                }
            }
        }
    }

    // Interaktívna slučka
    std::string line;
    while (client.is_connected()) {
        std::cout << client.current_path() << " > " << std::flush;

        if (!std::getline(std::cin, line)) {
            break;
        }

        // Parsovanie príkazu
        auto cmd = minidrive::client::CommandParser::parse(line);
        if (!cmd) {
            continue;
        }

        // Spracovanie príkazu
        if (cmd->name == "HELP") {
            std::cout << minidrive::client::HELP_TEXT << "\n";
            continue;
        }

        if (cmd->name == "EXIT" || cmd->name == "QUIT") {
            break;
        }

        if (cmd->name == "LIST" || cmd->name == "LS") {
            auto resp = client.list(cmd->arg_or(0, ""));
            print_response(resp);
            continue;
        }

        if (cmd->name == "CD") {
            if (!cmd->has_arg(0)) {
                std::cout << "ERROR: Path required\n";
                continue;
            }
            auto resp = client.cd(cmd->arg(0));
            print_response(resp);
            continue;
        }

        if (cmd->name == "MKDIR") {
            if (!cmd->has_arg(0)) {
                std::cout << "ERROR: Path required\n";
                continue;
            }
            auto resp = client.mkdir(cmd->arg(0));
            print_response(resp);
            continue;
        }

        if (cmd->name == "RMDIR") {
            if (!cmd->has_arg(0)) {
                std::cout << "ERROR: Path required\n";
                continue;
            }
            auto resp = client.rmdir(cmd->arg(0));
            print_response(resp);
            continue;
        }

        if (cmd->name == "DELETE" || cmd->name == "DEL" || cmd->name == "RM") {
            if (!cmd->has_arg(0)) {
                std::cout << "ERROR: Path required\n";
                continue;
            }
            auto resp = client.delete_file(cmd->arg(0));
            print_response(resp);
            continue;
        }

        if (cmd->name == "MOVE" || cmd->name == "MV") {
            if (!cmd->has_arg(1)) {
                std::cout << "ERROR: Source and destination required\n";
                continue;
            }
            auto resp = client.move(cmd->arg(0), cmd->arg(1));
            print_response(resp);
            continue;
        }

        if (cmd->name == "COPY" || cmd->name == "CP") {
            if (!cmd->has_arg(1)) {
                std::cout << "ERROR: Source and destination required\n";
                continue;
            }
            auto resp = client.copy(cmd->arg(0), cmd->arg(1));
            print_response(resp);
            continue;
        }

        if (cmd->name == "UPLOAD") {
            if (!cmd->has_arg(0)) {
                std::cout << "ERROR: Local path required\n";
                continue;
            }
            std::cout << "Uploading " << cmd->arg(0) << "...\n";
            auto resp = client.upload(cmd->arg(0), cmd->arg_or(1, ""), print_progress);
            print_response(resp);
            continue;
        }

        if (cmd->name == "DOWNLOAD") {
            if (!cmd->has_arg(0)) {
                std::cout << "ERROR: Remote path required\n";
                continue;
            }
            std::cout << "Downloading " << cmd->arg(0) << "...\n";
            auto resp = client.download(cmd->arg(0), cmd->arg_or(1, ""), print_progress);
            print_response(resp);
            continue;
        }

        if (cmd->name == "SYNC") {
            if (!cmd->has_arg(1)) {
                std::cout << "ERROR: Usage: SYNC <local_dir> <remote_dir>\n";
                continue;
            }
            
            std::string local_dir = cmd->arg(0);
            std::string remote_dir = cmd->arg(1);
            
            std::cout << "Synchronizing " << local_dir << " -> " << remote_dir << "...\n";
            
            auto result = client.sync(local_dir, remote_dir, print_progress);
            
            // Výpis správ
            for (const auto& msg : result.messages) {
                std::cout << msg << "\n";
            }
            
            // Súhrn
            std::cout << "\nSync complete:\n";
            std::cout << "  Uploaded: " << result.uploaded << "\n";
            std::cout << "  Deleted:  " << result.deleted << "\n";
            std::cout << "  Skipped:  " << result.skipped << "\n";
            if (result.errors > 0) {
                std::cout << "  Errors:   " << result.errors << "\n";
            }
            continue;
        }

        std::cout << "ERROR: Unknown command: " << cmd->name << "\n";
        std::cout << "Type HELP for list of commands\n";
    }

    client.disconnect();
    std::cout << "Goodbye!\n";

    return 0;
}
