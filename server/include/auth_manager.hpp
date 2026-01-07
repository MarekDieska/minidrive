#pragma once

#include "minidrive/minidrive.hpp"

#include <sodium.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace minidrive::server {

namespace fs = std::filesystem;

// Správca autentifikácie - hashované heslá so salt
class AuthManager {
public:
    explicit AuthManager(fs::path users_root)
        : users_root_(std::move(users_root))
        , db_path_(users_root_ / "users.json")
    {
        (void)PathUtils::create_directories(users_root_);
        load_database();
    }

    // Registrácia nového užívateľa
    [[nodiscard]] Response register_user(const std::string& username, const std::string& password) {
        std::lock_guard lock(mutex_);

        // Validácia username
        if (username.empty() || username.length() > 64) {
            return Response::error(ErrorCode::INVALID_ARGUMENT, "Invalid username");
        }

        // Kontrola či obsahuje len povolené znaky
        for (char c : username) {
            if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-') {
                return Response::error(ErrorCode::INVALID_ARGUMENT, 
                    "Username can only contain alphanumeric characters, _ and -");
            }
        }

        // Kontrola či užívateľ existuje
        if (users_.contains(username)) {
            return Response::error(ErrorCode::USER_ALREADY_EXISTS);
        }

        // Validácia hesla
        if (password.length() < 4) {
            return Response::error(ErrorCode::INVALID_ARGUMENT, "Password too short (min 4 chars)");
        }

        // Hash hesla
        auto hashed = hash_password(password);
        if (!hashed) {
            return Response::error(ErrorCode::SERVER_ERROR, "Failed to hash password");
        }

        // Vytvoríme užívateľa
        UserInfo user;
        user.username = username;
        user.password_hash = *hashed;
        user.created_at = std::time(nullptr);

        users_[username] = user;

        // Vytvoríme priečinok pre užívateľa
        fs::path user_dir = users_root_ / username;
        (void)PathUtils::create_directories(user_dir);

        // Uložíme databázu
        save_database();

        spdlog::info("User registered: {}", username);
        return Response::ok("User registered successfully");
    }

    // Autentifikácia užívateľa
    [[nodiscard]] Response authenticate(const std::string& username, const std::string& password) {
        std::lock_guard lock(mutex_);

        auto it = users_.find(username);
        if (it == users_.end()) {
            return Response::error(ErrorCode::USER_NOT_FOUND);
        }

        // Verifikácia hesla
        if (!verify_password(password, it->second.password_hash)) {
            return Response::error(ErrorCode::AUTH_FAILED, "Invalid password");
        }

        spdlog::info("User authenticated: {}", username);
        return Response::ok("Authentication successful");
    }

    // Kontrola či užívateľ existuje
    [[nodiscard]] bool user_exists(const std::string& username) {
        std::lock_guard lock(mutex_);
        return users_.contains(username);
    }

    // Získanie cesty k user directory
    [[nodiscard]] fs::path get_user_directory(const std::string& username) const {
        return users_root_ / username;
    }

private:
    struct UserInfo {
        std::string username;
        std::string password_hash;  // Argon2id hash (obsahuje salt)
        std::time_t created_at = 0;
    };

    // Hash hesla pomocou Argon2id
    [[nodiscard]] std::optional<std::string> hash_password(const std::string& password) {
        // Argon2id - odporúčaný pre password hashing
        // Output obsahuje salt, parametre aj hash
        std::array<char, crypto_pwhash_STRBYTES> hashed{};

        int result = crypto_pwhash_str(
            hashed.data(),
            password.c_str(),
            password.length(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE
        );

        if (result != 0) {
            spdlog::error("Password hashing failed");
            return std::nullopt;
        }

        return std::string(hashed.data());
    }

    // Verifikácia hesla
    [[nodiscard]] bool verify_password(const std::string& password, const std::string& hash) {
        return crypto_pwhash_str_verify(
            hash.c_str(),
            password.c_str(),
            password.length()
        ) == 0;
    }

    // Načítanie databázy z JSON súboru
    void load_database() {
        if (!PathUtils::exists(db_path_)) {
            spdlog::info("No user database found, starting fresh");
            return;
        }

        try {
            std::ifstream file(db_path_);
            if (!file) {
                spdlog::warn("Cannot open user database");
                return;
            }

            nlohmann::json j;
            file >> j;

            for (const auto& [username, data] : j.items()) {
                UserInfo user;
                user.username = username;
                user.password_hash = data.at("password_hash").get<std::string>();
                user.created_at = data.value("created_at", 0);
                users_[username] = user;
            }

            spdlog::info("Loaded {} users from database", users_.size());
        } catch (const std::exception& e) {
            spdlog::error("Failed to load user database: {}", e.what());
        }
    }

    // Uloženie databázy do JSON súboru
    void save_database() {
        try {
            nlohmann::json j;

            for (const auto& [username, user] : users_) {
                j[username] = {
                    {"password_hash", user.password_hash},
                    {"created_at", user.created_at}
                };
            }

            std::ofstream file(db_path_);
            if (!file) {
                spdlog::error("Cannot write user database");
                return;
            }

            file << j.dump(2);
            spdlog::debug("User database saved");
        } catch (const std::exception& e) {
            spdlog::error("Failed to save user database: {}", e.what());
        }
    }

    fs::path users_root_;
    fs::path db_path_;
    std::unordered_map<std::string, UserInfo> users_;
    mutable std::mutex mutex_;
};

} // namespace minidrive::server
