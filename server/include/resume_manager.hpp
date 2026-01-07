#pragma once

#include "minidrive/minidrive.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace minidrive::server {

namespace fs = std::filesystem;

// Informácie o prerušenom uploade
struct PendingUpload {
    std::string username;
    std::string remote_path;      // Cieľová cesta na serveri
    std::string part_path;        // Cesta k .part súboru
    std::uint64_t expected_size = 0;
    std::string expected_hash;
    std::uint64_t bytes_received = 0;
    std::time_t started_at = 0;
    std::time_t updated_at = 0;
};

// Manager pre resume transferov
class ResumeManager {
public:
    // Timeout pre nedokončené uploady (1 hodina)
    static constexpr std::chrono::seconds UPLOAD_TIMEOUT{3600};

    explicit ResumeManager(fs::path data_dir)
        : data_dir_(std::move(data_dir))
        , db_path_(data_dir_ / "pending_uploads.json")
    {
        (void)PathUtils::create_directories(data_dir_);
        load_database();
        cleanup_expired();
    }

    ~ResumeManager() {
        save_database();
    }

    // Registrácia nového uploadu
    void register_upload(const std::string& username, const PendingUpload& upload) {
        std::lock_guard lock(mutex_);
        
        std::string key = make_key(username, upload.remote_path);
        pending_uploads_[key] = upload;
        pending_uploads_[key].started_at = std::time(nullptr);
        pending_uploads_[key].updated_at = std::time(nullptr);
        
        save_database();
        spdlog::debug("Registered pending upload: {} -> {}", username, upload.remote_path);
    }

    // Aktualizácia progresu
    void update_progress(const std::string& username, const std::string& remote_path, 
                         std::uint64_t bytes_received) {
        std::lock_guard lock(mutex_);
        
        std::string key = make_key(username, remote_path);
        auto it = pending_uploads_.find(key);
        if (it != pending_uploads_.end()) {
            it->second.bytes_received = bytes_received;
            it->second.updated_at = std::time(nullptr);
        }
    }

    // Dokončenie uploadu - odstránenie z pending
    void complete_upload(const std::string& username, const std::string& remote_path) {
        std::lock_guard lock(mutex_);
        
        std::string key = make_key(username, remote_path);
        pending_uploads_.erase(key);
        save_database();
        
        spdlog::debug("Completed upload: {} -> {}", username, remote_path);
    }

    // Zrušenie uploadu
    void cancel_upload(const std::string& username, const std::string& remote_path) {
        std::lock_guard lock(mutex_);
        
        std::string key = make_key(username, remote_path);
        auto it = pending_uploads_.find(key);
        if (it != pending_uploads_.end()) {
            // Zmažeme .part súbor
            (void)PathUtils::remove_file(it->second.part_path);
            pending_uploads_.erase(it);
            save_database();
        }
    }

    // Získanie pending uploadu pre užívateľa
    [[nodiscard]] std::optional<PendingUpload> get_pending_upload(const std::string& username) {
        std::lock_guard lock(mutex_);
        
        for (const auto& [key, upload] : pending_uploads_) {
            if (upload.username == username) {
                return upload;
            }
        }
        return std::nullopt;
    }

    // Získanie všetkých pending uploadov pre užívateľa
    [[nodiscard]] std::vector<PendingUpload> get_all_pending(const std::string& username) {
        std::lock_guard lock(mutex_);
        
        std::vector<PendingUpload> result;
        for (const auto& [key, upload] : pending_uploads_) {
            if (upload.username == username) {
                result.push_back(upload);
            }
        }
        return result;
    }

    // Kontrola či existuje pending upload
    [[nodiscard]] bool has_pending_upload(const std::string& username, const std::string& remote_path) {
        std::lock_guard lock(mutex_);
        std::string key = make_key(username, remote_path);
        return pending_uploads_.contains(key);
    }

    // Získanie bytes received pre resume
    [[nodiscard]] std::uint64_t get_bytes_received(const std::string& username, 
                                                    const std::string& remote_path) {
        std::lock_guard lock(mutex_);
        
        std::string key = make_key(username, remote_path);
        auto it = pending_uploads_.find(key);
        if (it != pending_uploads_.end()) {
            // Verifikujeme že .part súbor existuje a má správnu veľkosť
            if (PathUtils::exists(it->second.part_path)) {
                auto actual_size = PathUtils::file_size(it->second.part_path);
                if (actual_size && *actual_size == it->second.bytes_received) {
                    return it->second.bytes_received;
                }
            }
            // .part súbor neexistuje alebo má inú veľkosť - resetujeme
            pending_uploads_.erase(it);
            save_database();
        }
        return 0;
    }

    // Cleanup expirovaných uploadov
    void cleanup_expired() {
        std::lock_guard lock(mutex_);
        
        auto now = std::time(nullptr);
        std::vector<std::string> to_remove;
        
        for (const auto& [key, upload] : pending_uploads_) {
            auto age = std::chrono::seconds(now - upload.updated_at);
            if (age > UPLOAD_TIMEOUT) {
                // Zmažeme .part súbor
                (void)PathUtils::remove_file(upload.part_path);
                to_remove.push_back(key);
                spdlog::info("Cleaned up expired upload: {}", upload.remote_path);
            }
        }
        
        for (const auto& key : to_remove) {
            pending_uploads_.erase(key);
        }
        
        if (!to_remove.empty()) {
            save_database();
        }
    }

    // Uloženie stavu (volať pri SIGTERM)
    void save_state() {
        std::lock_guard lock(mutex_);
        save_database();
    }

private:
    std::string make_key(const std::string& username, const std::string& path) const {
        return username + ":" + path;
    }

    void load_database() {
        if (!PathUtils::exists(db_path_)) {
            return;
        }

        try {
            std::ifstream file(db_path_);
            if (!file) return;

            nlohmann::json j;
            file >> j;

            for (const auto& [key, data] : j.items()) {
                PendingUpload upload;
                upload.username = data.at("username").get<std::string>();
                upload.remote_path = data.at("remote_path").get<std::string>();
                upload.part_path = data.at("part_path").get<std::string>();
                upload.expected_size = data.at("expected_size").get<std::uint64_t>();
                upload.expected_hash = data.value("expected_hash", "");
                upload.bytes_received = data.at("bytes_received").get<std::uint64_t>();
                upload.started_at = data.at("started_at").get<std::time_t>();
                upload.updated_at = data.at("updated_at").get<std::time_t>();
                
                pending_uploads_[key] = upload;
            }

            spdlog::info("Loaded {} pending uploads", pending_uploads_.size());
        } catch (const std::exception& e) {
            spdlog::error("Failed to load pending uploads: {}", e.what());
        }
    }

    void save_database() {
        try {
            nlohmann::json j;

            for (const auto& [key, upload] : pending_uploads_) {
                j[key] = {
                    {"username", upload.username},
                    {"remote_path", upload.remote_path},
                    {"part_path", upload.part_path},
                    {"expected_size", upload.expected_size},
                    {"expected_hash", upload.expected_hash},
                    {"bytes_received", upload.bytes_received},
                    {"started_at", upload.started_at},
                    {"updated_at", upload.updated_at}
                };
            }

            std::ofstream file(db_path_);
            if (file) {
                file << j.dump(2);
            }
        } catch (const std::exception& e) {
            spdlog::error("Failed to save pending uploads: {}", e.what());
        }
    }

    fs::path data_dir_;
    fs::path db_path_;
    std::unordered_map<std::string, PendingUpload> pending_uploads_;
    mutable std::mutex mutex_;
};

} // namespace minidrive::server
