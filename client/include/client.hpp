#pragma once

#include "minidrive/minidrive.hpp"

#include <spdlog/spdlog.h>

#include <filesystem>
#include <fstream>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>

namespace minidrive::client {

namespace fs = std::filesystem;

// Callback pre progress uploadu/downloadu
using ProgressCallback = std::function<void(std::uint64_t current, std::uint64_t total)>;

// Klient pre komunikáciu so serverom
class Client {
public:
    struct Config {
        std::string host;
        std::uint16_t port = 9000;
        std::optional<std::string> username;
        std::optional<std::string> log_file;
    };

    explicit Client(Config config)
        : config_(std::move(config))
    {}

    ~Client() {
        disconnect();
    }

    // Disable copy
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    // Pripojenie na server
    [[nodiscard]] bool connect() {
        // Inicializácia libsodium
        if (!HashUtils::init()) {
            last_error_ = "Failed to initialize crypto library";
            return false;
        }

        // Vytvoríme socket
        auto socket_result = Socket::create_tcp();
        if (!socket_result) {
            last_error_ = "Failed to create socket: " + std::string(strerror(socket_result.error()));
            return false;
        }
        socket_ = std::move(*socket_result);

        // Pripojíme sa
        auto connect_result = socket_.connect(config_.host, config_.port);
        if (!connect_result) {
            last_error_ = "Failed to connect: " + std::string(strerror(connect_result.error()));
            socket_.close();
            return false;
        }

        connected_ = true;
        return true;
    }

    // Odpojenie
    void disconnect() {
        if (connected_) {
            // Pošleme DISCONNECT
            Request req;
            req.cmd = "DISCONNECT";
            (void)socket_.send_message(req);
            socket_.close();
            connected_ = false;
        }
    }

    // Kontrola pripojenia
    [[nodiscard]] bool is_connected() const noexcept {
        return connected_;
    }

    // Získanie poslednej chyby
    [[nodiscard]] const std::string& last_error() const noexcept {
        return last_error_;
    }

    // Kontrola autentifikácie
    [[nodiscard]] bool is_authenticated() const noexcept {
        return authenticated_;
    }

    // === Autentifikácia ===

    // AUTH - prihlásenie existujúceho užívateľa
    [[nodiscard]] Response authenticate(const std::string& username, const std::string& password) {
        Request req;
        req.cmd = "AUTH";
        req.username = username;
        req.password = password;
        auto resp = send_request(req);
        if (resp.is_ok()) {
            authenticated_ = true;
            username_ = username;
            if (resp.current_path) {
                current_path_ = *resp.current_path;
            }
        }
        return resp;
    }

    // REGISTER - registrácia nového užívateľa
    [[nodiscard]] Response register_user(const std::string& username, const std::string& password) {
        Request req;
        req.cmd = "REGISTER";
        req.username = username;
        req.password = password;
        return send_request(req);
    }

    // Kontrola či užívateľ existuje (cez AUTH s prázdnym heslom, vráti USER_NOT_FOUND alebo AUTH_FAILED)
    [[nodiscard]] bool user_exists(const std::string& username) {
        Request req;
        req.cmd = "AUTH";
        req.username = username;
        req.password = "";  // Prázdne heslo
        auto resp = send_request(req);
        // Ak vráti AUTH_FAILED, užívateľ existuje (len zlé heslo)
        // Ak vráti USER_NOT_FOUND, užívateľ neexistuje
        return resp.error_code() != ErrorCode::USER_NOT_FOUND;
    }

    // === Resume ===

    // Štruktúra pre pending upload
    struct PendingUploadInfo {
        std::string remote_path;
        std::uint64_t total_size = 0;
        std::uint64_t bytes_uploaded = 0;
        std::string hash;
    };

    // Získanie zoznamu pending uploadov
    [[nodiscard]] std::vector<PendingUploadInfo> get_pending_uploads() {
        std::vector<PendingUploadInfo> result;
        
        Request req;
        req.cmd = "RESUME_LIST";
        auto resp = send_request(req);
        
        if (resp.is_ok() && resp.files) {
            for (const auto& f : *resp.files) {
                PendingUploadInfo info;
                info.remote_path = f.name;
                info.total_size = f.size;
                info.bytes_uploaded = static_cast<std::uint64_t>(f.modified_time);  // Hack - bytes_received
                info.hash = f.hash;
                result.push_back(info);
            }
        }
        
        return result;
    }

    // Pokračovanie v uploade
    [[nodiscard]] Response resume_upload(
        const fs::path& local_path,
        const std::string& remote_path,
        [[maybe_unused]] std::uint64_t offset,
        ProgressCallback progress = nullptr
    ) {
        // Kontrola lokálneho súboru
        if (!PathUtils::is_file(local_path)) {
            return Response::error(ErrorCode::FILE_NOT_FOUND, "Local file not found");
        }

        auto file_size = PathUtils::file_size(local_path);
        if (!file_size) {
            return Response::error(ErrorCode::FILE_READ_ERROR, "Cannot read file size");
        }

        // Pošleme RESUME_UPLOAD request
        Request req;
        req.cmd = "RESUME_UPLOAD";
        req.path = remote_path;
        
        auto init_resp = send_request(req);
        if (!init_resp.is_ok()) {
            return init_resp;
        }

        // Server potvrdil offset
        std::uint64_t server_offset = init_resp.offset.value_or(0);
        
        // Otvoríme súbor a preskočíme na offset
        std::ifstream file(local_path, std::ios::binary);
        if (!file) {
            return Response::error(ErrorCode::FILE_READ_ERROR, "Cannot open file");
        }
        file.seekg(static_cast<std::streamoff>(server_offset));

        // Posielame chunky
        std::array<char, protocol::CHUNK_SIZE> buffer{};
        std::uint64_t total_sent = server_offset;

        while (file && total_sent < *file_size) {
            file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            auto bytes_read = static_cast<std::size_t>(file.gcount());

            if (bytes_read == 0) break;

            std::string encoded = Base64::encode(std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(buffer.data()),
                bytes_read
            ));

            Request chunk_req;
            chunk_req.cmd = "CHUNK";
            chunk_req.data = std::move(encoded);

            auto chunk_resp = send_request(chunk_req);
            if (!chunk_resp.is_ok()) {
                return chunk_resp;
            }

            total_sent += bytes_read;

            if (progress) {
                progress(total_sent, *file_size);
            }
        }

        return Response::ok("Upload complete");
    }

    // === Príkazy ===

    // LIST
    [[nodiscard]] Response list(const std::string& path = "") {
        Request req;
        req.cmd = "LIST";
        if (!path.empty()) {
            req.path = path;
        }
        return send_request(req);
    }

    // CD
    [[nodiscard]] Response cd(const std::string& path) {
        Request req;
        req.cmd = "CD";
        req.path = path;
        auto resp = send_request(req);
        if (resp.is_ok() && resp.current_path) {
            current_path_ = *resp.current_path;
        }
        return resp;
    }

    // MKDIR
    [[nodiscard]] Response mkdir(const std::string& path) {
        Request req;
        req.cmd = "MKDIR";
        req.path = path;
        return send_request(req);
    }

    // RMDIR
    [[nodiscard]] Response rmdir(const std::string& path) {
        Request req;
        req.cmd = "RMDIR";
        req.path = path;
        return send_request(req);
    }

    // DELETE
    [[nodiscard]] Response delete_file(const std::string& path) {
        Request req;
        req.cmd = "DELETE";
        req.path = path;
        return send_request(req);
    }

    // MOVE
    [[nodiscard]] Response move(const std::string& src, const std::string& dst) {
        Request req;
        req.cmd = "MOVE";
        req.path = src;
        req.dest = dst;
        return send_request(req);
    }

    // COPY
    [[nodiscard]] Response copy(const std::string& src, const std::string& dst) {
        Request req;
        req.cmd = "COPY";
        req.path = src;
        req.dest = dst;
        return send_request(req);
    }

    // UPLOAD
    [[nodiscard]] Response upload(
        const fs::path& local_path,
        const std::string& remote_path = "",
        ProgressCallback progress = nullptr
    ) {
        // Kontrola lokálneho súboru
        if (!PathUtils::is_file(local_path)) {
            return Response::error(ErrorCode::FILE_NOT_FOUND, "Local file not found");
        }

        auto file_size = PathUtils::file_size(local_path);
        if (!file_size) {
            return Response::error(ErrorCode::FILE_READ_ERROR, "Cannot read file size");
        }

        if (*file_size > protocol::MAX_FILE_SIZE) {
            return Response::error(ErrorCode::FILE_TOO_LARGE);
        }

        // Vypočítame hash
        auto hash = HashUtils::hash_file_hex(local_path);
        if (!hash) {
            return Response::error(ErrorCode::FILE_READ_ERROR, "Cannot compute hash");
        }

        // Určíme remote path
        std::string dest = remote_path.empty() ? local_path.filename().string() : remote_path;

        // Inicializácia uploadu
        Request init_req;
        init_req.cmd = "UPLOAD";
        init_req.path = dest;
        init_req.size = *file_size;
        init_req.hash = *hash;

        auto init_resp = send_request(init_req);
        if (!init_resp.is_ok()) {
            return init_resp;
        }

        // Otvoríme súbor
        std::ifstream file(local_path, std::ios::binary);
        if (!file) {
            return Response::error(ErrorCode::FILE_READ_ERROR, "Cannot open file");
        }

        // Posielame chunky
        std::array<char, protocol::CHUNK_SIZE> buffer{};
        std::uint64_t total_sent = 0;

        while (file && total_sent < *file_size) {
            file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            auto bytes_read = static_cast<std::size_t>(file.gcount());

            if (bytes_read == 0) {
                break;
            }

            // Enkódujeme do base64
            std::string encoded = Base64::encode(std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(buffer.data()),
                bytes_read
            ));

            Request chunk_req;
            chunk_req.cmd = "CHUNK";
            chunk_req.data = std::move(encoded);

            auto chunk_resp = send_request(chunk_req);
            if (!chunk_resp.is_ok()) {
                return chunk_resp;
            }

            total_sent += bytes_read;

            if (progress) {
                progress(total_sent, *file_size);
            }
        }

        return Response::ok("Upload complete");
    }

    // DOWNLOAD
    [[nodiscard]] Response download(
        const std::string& remote_path,
        const fs::path& local_path = "",
        ProgressCallback progress = nullptr
    ) {
        // Určíme lokálnu cestu
        fs::path dest = local_path;
        if (dest.empty()) {
            dest = fs::path(remote_path).filename();
        }

        // Kontrola či súbor neexistuje
        if (PathUtils::exists(dest)) {
            return Response::error(ErrorCode::FILE_ALREADY_EXISTS,
                                   "Local file already exists");
        }

        // Požiadavka na download
        Request req;
        req.cmd = "DOWNLOAD";
        req.path = remote_path;

        auto init_resp = send_request(req);
        if (!init_resp.is_ok()) {
            return init_resp;
        }

        if (!init_resp.size) {
            return Response::error(ErrorCode::SERVER_ERROR, "Server did not send file size");
        }

        std::uint64_t total_size = *init_resp.size;
        std::string expected_hash = init_resp.hash.value_or("");

        // Otvoríme súbor pre zápis
        fs::path part_path = dest;
        part_path += ".part";

        std::ofstream file(part_path, std::ios::binary | std::ios::trunc);
        if (!file) {
            return Response::error(ErrorCode::FILE_WRITE_ERROR, "Cannot create file");
        }

        HashStream hasher;
        std::uint64_t total_received = 0;

        // Prijímame chunky
        while (total_received < total_size) {
            auto msg_result = socket_.recv_message();
            if (!msg_result) {
                file.close();
                (void)PathUtils::remove_file(part_path);
                return Response::error(ErrorCode::CONNECTION_LOST);
            }

            Response chunk_resp;
            try {
                chunk_resp = Response::from_json(*msg_result);
            } catch (const std::exception& e) {
                file.close();
                (void)PathUtils::remove_file(part_path);
                return Response::error(ErrorCode::SERVER_ERROR, e.what());
            }

            // Kontrola či nie je finálna správa
            if (chunk_resp.message != "CHUNK") {
                break;
            }

            if (!chunk_resp.data) {
                continue;
            }

            auto decoded = Base64::decode(*chunk_resp.data);
            if (!decoded) {
                file.close();
                (void)PathUtils::remove_file(part_path);
                return Response::error(ErrorCode::CHUNK_ERROR, "Invalid chunk data");
            }

            file.write(reinterpret_cast<const char*>(decoded->data()),
                      static_cast<std::streamsize>(decoded->size()));

            if (!file) {
                file.close();
                (void)PathUtils::remove_file(part_path);
                return Response::error(ErrorCode::FILE_WRITE_ERROR);
            }

            hasher.update(*decoded);
            total_received += decoded->size();

            if (progress) {
                progress(total_received, total_size);
            }
        }

        file.close();

        // Verifikácia hashu
        std::string actual_hash = hasher.finalize_hex();
        if (!expected_hash.empty() && actual_hash != expected_hash) {
            (void)PathUtils::remove_file(part_path);
            return Response::error(ErrorCode::FILE_HASH_MISMATCH);
        }

        // Presunieme na finálne miesto
        if (!PathUtils::rename(part_path, dest)) {
            (void)PathUtils::remove_file(part_path);
            return Response::error(ErrorCode::FILE_WRITE_ERROR, "Cannot rename file");
        }

        return Response::ok("Download complete");
    }

    // HASH_LIST - získanie zoznamu súborov s hashmi
    [[nodiscard]] Response hash_list(const std::string& path = "") {
        Request req;
        req.cmd = "HASH_LIST";
        if (!path.empty()) {
            req.path = path;
        }
        return send_request(req);
    }

    // Štruktúra pre výsledok SYNC
    struct SyncResult {
        int uploaded = 0;
        int deleted = 0;
        int skipped = 0;
        int errors = 0;
        std::vector<std::string> messages;
    };

    // SYNC - synchronizácia lokálneho priečinka na server
    [[nodiscard]] SyncResult sync(
        const fs::path& local_dir,
        const std::string& remote_dir,
        ProgressCallback progress = nullptr
    ) {
        SyncResult result;

        // Kontrola lokálneho priečinka
        if (!PathUtils::is_directory(local_dir)) {
            result.errors++;
            result.messages.push_back("Local directory not found: " + local_dir.string());
            return result;
        }

        // Získame zoznam súborov na serveri
        auto server_resp = hash_list(remote_dir);
        
        std::unordered_map<std::string, FileInfo> server_files;
        if (server_resp.is_ok() && server_resp.files) {
            for (const auto& f : *server_resp.files) {
                server_files[f.name] = f;
            }
        }

        // Získame zoznam lokálnych súborov
        std::unordered_map<std::string, fs::path> local_files;
        std::unordered_map<std::string, std::string> local_hashes;
        
        collect_local_files(local_dir, "", local_files, local_hashes);

        // 1. Upload nových a zmenených súborov
        for (const auto& [rel_path, local_path] : local_files) {
            std::string remote_path = remote_dir.empty() 
                ? rel_path 
                : remote_dir + "/" + rel_path;

            auto it = server_files.find(rel_path);
            if (it == server_files.end()) {
                // Súbor neexistuje na serveri - upload
                result.messages.push_back("Uploading: " + rel_path);
                auto resp = upload(local_path, remote_path, progress);
                if (resp.is_ok()) {
                    result.uploaded++;
                } else {
                    result.errors++;
                    result.messages.push_back("  Error: " + resp.message);
                }
            } else {
                // Súbor existuje - porovnáme hash
                const auto& local_hash = local_hashes[rel_path];
                if (local_hash != it->second.hash) {
                    // Hash sa líši - najprv zmažeme starý, potom uploadneme
                    result.messages.push_back("Updating: " + rel_path);
                    auto del_resp = delete_file(remote_path);
                    if (del_resp.is_ok()) {
                        auto up_resp = upload(local_path, remote_path, progress);
                        if (up_resp.is_ok()) {
                            result.uploaded++;
                        } else {
                            result.errors++;
                            result.messages.push_back("  Upload error: " + up_resp.message);
                        }
                    } else {
                        result.errors++;
                        result.messages.push_back("  Delete error: " + del_resp.message);
                    }
                } else {
                    // Hash sa zhoduje - preskočíme
                    result.skipped++;
                }
                // Odstránime zo server_files (zostanú len súbory na zmazanie)
                server_files.erase(it);
            }
        }

        // 2. Zmazanie súborov ktoré neexistujú lokálne
        for (const auto& [rel_path, info] : server_files) {
            std::string remote_path = remote_dir.empty() 
                ? rel_path 
                : remote_dir + "/" + rel_path;
            
            result.messages.push_back("Deleting: " + rel_path);
            auto resp = delete_file(remote_path);
            if (resp.is_ok()) {
                result.deleted++;
            } else {
                result.errors++;
                result.messages.push_back("  Error: " + resp.message);
            }
        }

        return result;
    }

    // Získanie aktuálnej cesty
    [[nodiscard]] const std::string& current_path() const noexcept {
        return current_path_;
    }

private:
    // Rekurzívne zbieranie lokálnych súborov
    void collect_local_files(
        const fs::path& dir,
        const std::string& prefix,
        std::unordered_map<std::string, fs::path>& files,
        std::unordered_map<std::string, std::string>& hashes
    ) {
        std::error_code ec;
        for (const auto& entry : fs::directory_iterator(dir, ec)) {
            if (ec) continue;

            std::string name = prefix.empty() 
                ? entry.path().filename().string() 
                : prefix + "/" + entry.path().filename().string();

            if (entry.is_directory(ec)) {
                collect_local_files(entry.path(), name, files, hashes);
            } else if (entry.is_regular_file(ec)) {
                files[name] = entry.path();
                auto hash = HashUtils::hash_file_hex(entry.path());
                if (hash) {
                    hashes[name] = *hash;
                }
            }
        }
    }
    // Odoslanie požiadavky a prijatie odpovede
    Response send_request(const Request& req) {
        if (!connected_) {
            return Response::error(ErrorCode::CONNECTION_LOST, "Not connected");
        }

        auto send_result = socket_.send_message(req);
        if (!send_result) {
            connected_ = false;
            return Response::error(ErrorCode::CONNECTION_LOST,
                                   "Send failed: " + std::string(strerror(send_result.error())));
        }

        auto recv_result = socket_.recv_message();
        if (!recv_result) {
            connected_ = false;
            return Response::error(ErrorCode::CONNECTION_LOST,
                                   "Receive failed: " + std::string(strerror(recv_result.error())));
        }

        try {
            return Response::from_json(*recv_result);
        } catch (const std::exception& e) {
            return Response::error(ErrorCode::SERVER_ERROR,
                                   "Invalid response: " + std::string(e.what()));
        }
    }

    Config config_;
    Socket socket_;
    bool connected_ = false;
    bool authenticated_ = false;
    std::string username_;
    std::string current_path_ = "/";
    std::string last_error_;
};

} // namespace minidrive::client
