#pragma once

#include "file_manager.hpp"
#include "user_file_manager.hpp"
#include "auth_manager.hpp"
#include "resume_manager.hpp"
#include "minidrive/minidrive.hpp"

#include <spdlog/spdlog.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

namespace minidrive::server {

// Handler pre jedného pripojeného klienta
class ClientHandler {
public:
    ClientHandler(
        Socket socket,
        std::string client_id,
        std::shared_ptr<FileManager> public_file_manager,
        std::shared_ptr<AuthManager> auth_manager,
        std::shared_ptr<ResumeManager> resume_manager,
        const fs::path& users_root,
        const fs::path& public_root
    )
        : socket_(std::move(socket))
        , client_id_(std::move(client_id))
        , file_manager_(std::move(public_file_manager))
        , auth_manager_(std::move(auth_manager))
        , resume_manager_(std::move(resume_manager))
        , users_root_(users_root)
        , public_root_(public_root)
    {}

    // Hlavná slučka spracovania klienta
    void run() {
        spdlog::info("[{}] Client handler started", client_id_);

        // Nastavíme timeout
        socket_.set_recv_timeout(protocol::CONNECTION_TIMEOUT);

        while (running_) {
            auto msg_result = socket_.recv_message();
            if (!msg_result) {
                if (msg_result.error() == EAGAIN || msg_result.error() == EWOULDBLOCK) {
                    spdlog::warn("[{}] Client timeout", client_id_);
                } else if (msg_result.error() == ECONNRESET) {
                    spdlog::info("[{}] Client disconnected", client_id_);
                } else {
                    spdlog::error("[{}] Receive error: {}", client_id_, strerror(msg_result.error()));
                }
                break;
            }

            if (msg_result->empty()) {
                continue;
            }

            spdlog::debug("[{}] Received: {}", client_id_, *msg_result);

            Response response;
            try {
                Request request = Request::from_json(*msg_result);
                response = handle_request(request);
            } catch (const nlohmann::json::exception& e) {
                spdlog::error("[{}] JSON parse error: {}", client_id_, e.what());
                response = Response::error(ErrorCode::INVALID_COMMAND, e.what());
            } catch (const std::exception& e) {
                spdlog::error("[{}] Request error: {}", client_id_, e.what());
                response = Response::error(ErrorCode::SERVER_ERROR, e.what());
            }

            auto send_result = socket_.send_message(response);
            if (!send_result) {
                spdlog::error("[{}] Send error: {}", client_id_, strerror(send_result.error()));
                break;
            }
        }

        spdlog::info("[{}] Client handler stopped", client_id_);
    }

    // Zastavenie handlera
    void stop() {
        running_ = false;
    }

    // Získanie ID klienta
    [[nodiscard]] const std::string& client_id() const noexcept {
        return client_id_;
    }

    // Kontrola či je autentifikovaný
    [[nodiscard]] bool is_authenticated() const noexcept {
        return authenticated_;
    }

    // Získanie username
    [[nodiscard]] const std::string& username() const noexcept {
        return username_;
    }

private:
    // Spracovanie požiadavky
    Response handle_request(const Request& req) {
        auto cmd_type = string_to_command_type(req.cmd);
        if (!cmd_type) {
            return Response::error(ErrorCode::INVALID_COMMAND,
                                   "Unknown command: " + req.cmd);
        }

        // AUTH a REGISTER sú povolené vždy
        if (*cmd_type == CommandType::AUTH) {
            return handle_auth(req);
        }
        if (*cmd_type == CommandType::REGISTER) {
            return handle_register(req);
        }

        // Ostatné príkazy
        switch (*cmd_type) {
            case CommandType::LIST:
                return handle_list(req);

            case CommandType::CD:
                return handle_cd(req);

            case CommandType::MKDIR:
                return handle_mkdir(req);

            case CommandType::RMDIR:
                return handle_rmdir(req);

            case CommandType::DELETE:
                return handle_delete(req);

            case CommandType::MOVE:
                return handle_move(req);

            case CommandType::COPY:
                return handle_copy(req);

            case CommandType::UPLOAD:
                return handle_upload_init(req);

            case CommandType::CHUNK:
                return handle_chunk(req);

            case CommandType::DOWNLOAD:
                return handle_download(req);

            case CommandType::HASH_LIST:
                return handle_hash_list(req);

            case CommandType::RESUME_LIST:
                return handle_resume_list(req);

            case CommandType::RESUME_UPLOAD:
                return handle_resume_upload(req);

            case CommandType::DISCONNECT:
                running_ = false;
                // Uložíme stav uploadu ak prebieha
                if (current_upload_ && authenticated_) {
                    resume_manager_->update_progress(username_, 
                        current_upload_remote_path_,
                        current_upload_->bytes_received);
                }
                return Response::ok("Goodbye");

            default:
                return Response::error(ErrorCode::INVALID_COMMAND,
                                       "Command not implemented: " + req.cmd);
        }
    }

    // RESUME_LIST handler - zoznam nedokončených transferov
    Response handle_resume_list([[maybe_unused]] const Request& req) {
        if (!authenticated_) {
            return Response::error(ErrorCode::AUTH_REQUIRED, 
                                   "Resume only available in authenticated mode");
        }

        auto pending = resume_manager_->get_all_pending(username_);
        
        std::vector<FileInfo> files;
        for (const auto& p : pending) {
            FileInfo info;
            info.name = p.remote_path;
            info.size = p.expected_size;
            info.hash = p.expected_hash;
            info.modified_time = static_cast<std::int64_t>(p.bytes_received);  // Hack: bytes_received v modified_time
            files.push_back(info);
        }

        auto resp = Response::ok();
        resp.files = std::move(files);
        return resp;
    }

    // RESUME_UPLOAD handler - continue interrupted upload
    Response handle_resume_upload(const Request& req) {
        if (!authenticated_) {
            return Response::error(ErrorCode::AUTH_REQUIRED,
                                   "Resume only available in authenticated mode");
        }

        if (!req.path) {
            return Response::error(ErrorCode::INVALID_ARGUMENT, "Path required");
        }

        // Find pending upload
        auto pending = resume_manager_->get_all_pending(username_);
        PendingUpload* found = nullptr;
        for (auto& p : pending) {
            if (p.remote_path == *req.path) {
                found = &p;
                break;
            }
        }

        if (!found) {
            return Response::error(ErrorCode::FILE_NOT_FOUND, "No pending upload found");
        }

        // Verify .part file exists
        if (!PathUtils::exists(found->part_path)) {
            resume_manager_->cancel_upload(username_, found->remote_path);
            return Response::error(ErrorCode::FILE_NOT_FOUND, "Part file not found");
        }

        // Set upload state
        UploadState upload_state;
        upload_state.path = fs::path(found->part_path).parent_path() / 
                           fs::path(found->remote_path).filename();
        upload_state.part_path = found->part_path;
        upload_state.expected_size = found->expected_size;
        upload_state.expected_hash = found->expected_hash;
        upload_state.bytes_received = found->bytes_received;

        // Recompute hash of existing data in .part file
        {
            std::ifstream part_file(upload_state.part_path, std::ios::binary);
            if (part_file) {
                std::array<std::uint8_t, 65536> buffer{};
                while (part_file) {
                    part_file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
                    auto bytes_read = part_file.gcount();
                    if (bytes_read > 0) {
                        upload_state.hasher.update(
                            std::span<const std::uint8_t>(buffer.data(), static_cast<std::size_t>(bytes_read))
                        );
                    }
                }
            }
        }

        // Open file for append
        upload_state.file.open(upload_state.part_path, std::ios::binary | std::ios::app);
        if (!upload_state.file) {
            return Response::error(ErrorCode::FILE_WRITE_ERROR);
        }
        
        current_upload_ = std::move(upload_state);
        current_upload_remote_path_ = *req.path;

        auto resp = Response::ok("Resume upload");
        resp.offset = found->bytes_received;
        resp.size = found->expected_size;
        return resp;
    }

    // HASH_LIST handler - získanie zoznamu súborov s hashmi pre SYNC
    Response handle_hash_list(const Request& req) {
        std::string path = req.path.value_or("");
        spdlog::debug("[{}] HASH_LIST {}", client_id_, path.empty() ? "." : path);
        
        if (authenticated_ && user_file_manager_) {
            return user_file_manager_->hash_list(path);
        }
        return file_manager_->hash_list(path);
    }

    // AUTH handler
    Response handle_auth(const Request& req) {
        if (!req.username || !req.password) {
            return Response::error(ErrorCode::INVALID_ARGUMENT, 
                                   "Username and password required");
        }

        // Kontrola či užívateľ existuje
        if (!auth_manager_->user_exists(*req.username)) {
            return Response::error(ErrorCode::USER_NOT_FOUND);
        }

        // Autentifikácia
        auto result = auth_manager_->authenticate(*req.username, *req.password);
        if (!result.is_ok()) {
            return result;
        }

        // Nastavíme authenticated mode
        authenticated_ = true;
        username_ = *req.username;

        // Pre authenticated usera vytvoríme UserFileManager s prístupom k private a public
        fs::path user_dir = auth_manager_->get_user_directory(username_);
        fs::path private_dir = user_dir / "private";
        (void)PathUtils::create_directories(private_dir);
        
        // Vytvoríme UserFileManager
        user_file_manager_ = std::make_shared<UserFileManager>(private_dir, public_root_);

        spdlog::info("[{}] User authenticated: {}", client_id_, username_);

        auto resp = Response::ok("Logged as " + username_);
        resp.current_path = "/";
        return resp;
    }

    // REGISTER handler
    Response handle_register(const Request& req) {
        if (!req.username || !req.password) {
            return Response::error(ErrorCode::INVALID_ARGUMENT, 
                                   "Username and password required");
        }

        auto result = auth_manager_->register_user(*req.username, *req.password);
        return result;
    }

    // LIST handler
    Response handle_list(const Request& req) {
        std::string path = req.path.value_or("");
        spdlog::debug("[{}] LIST {}", client_id_, path.empty() ? "." : path);
        
        if (authenticated_ && user_file_manager_) {
            return user_file_manager_->list_directory(path);
        }
        return file_manager_->list_directory(path);
    }

    // CD handler
    Response handle_cd(const Request& req) {
        if (!req.path) {
            return Response::error(ErrorCode::INVALID_ARGUMENT, "Path required");
        }
        spdlog::debug("[{}] CD {}", client_id_, *req.path);
        
        if (authenticated_ && user_file_manager_) {
            return user_file_manager_->change_directory(*req.path);
        }
        return file_manager_->change_directory(*req.path);
    }

    // MKDIR handler
    Response handle_mkdir(const Request& req) {
        if (!req.path) {
            return Response::error(ErrorCode::INVALID_ARGUMENT, "Path required");
        }
        spdlog::debug("[{}] MKDIR {}", client_id_, *req.path);
        
        if (authenticated_ && user_file_manager_) {
            return user_file_manager_->make_directory(*req.path);
        }
        return file_manager_->make_directory(*req.path);
    }

    // RMDIR handler
    Response handle_rmdir(const Request& req) {
        if (!req.path) {
            return Response::error(ErrorCode::INVALID_ARGUMENT, "Path required");
        }
        spdlog::debug("[{}] RMDIR {}", client_id_, *req.path);
        
        if (authenticated_ && user_file_manager_) {
            return user_file_manager_->remove_directory(*req.path);
        }
        return file_manager_->remove_directory(*req.path);
    }

    // DELETE handler
    Response handle_delete(const Request& req) {
        if (!req.path) {
            return Response::error(ErrorCode::INVALID_ARGUMENT, "Path required");
        }
        spdlog::debug("[{}] DELETE {}", client_id_, *req.path);
        
        if (authenticated_ && user_file_manager_) {
            return user_file_manager_->delete_file(*req.path);
        }
        return file_manager_->delete_file(*req.path);
    }

    // MOVE handler
    Response handle_move(const Request& req) {
        if (!req.path || !req.dest) {
            return Response::error(ErrorCode::INVALID_ARGUMENT, "Source and destination required");
        }
        spdlog::debug("[{}] MOVE {} -> {}", client_id_, *req.path, *req.dest);
        
        if (authenticated_ && user_file_manager_) {
            return user_file_manager_->move(*req.path, *req.dest);
        }
        return file_manager_->move(*req.path, *req.dest);
    }

    // COPY handler
    Response handle_copy(const Request& req) {
        if (!req.path || !req.dest) {
            return Response::error(ErrorCode::INVALID_ARGUMENT, "Source and destination required");
        }
        spdlog::debug("[{}] COPY {} -> {}", client_id_, *req.path, *req.dest);
        
        if (authenticated_ && user_file_manager_) {
            return user_file_manager_->copy(*req.path, *req.dest);
        }
        return file_manager_->copy(*req.path, *req.dest);
    }

    // UPLOAD inicializácia
    Response handle_upload_init(const Request& req) {
        if (!req.path || !req.size) {
            return Response::error(ErrorCode::INVALID_ARGUMENT,
                                   "Path and size required for upload");
        }

        spdlog::debug("[{}] UPLOAD {} (size: {})", client_id_, *req.path, *req.size);

        // Kontrola veľkosti
        if (*req.size > protocol::MAX_FILE_SIZE) {
            return Response::error(ErrorCode::FILE_TOO_LARGE);
        }

        // Resolve cesta
        std::optional<fs::path> resolved;
        if (authenticated_ && user_file_manager_) {
            resolved = user_file_manager_->resolve_path_safe(*req.path);
        } else {
            resolved = file_manager_->resolve_path_safe(*req.path);
        }
        
        if (!resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL_DENIED);
        }

        // Kontrola či súbor neexistuje
        if (PathUtils::exists(*resolved)) {
            return Response::error(ErrorCode::FILE_ALREADY_EXISTS);
        }

        // Vytvoríme parent directory
        (void)PathUtils::create_directories(resolved->parent_path());

        // Uložíme info o prebiehajúcom uploade
        UploadState upload_state;
        upload_state.path = *resolved;
        upload_state.expected_size = *req.size;
        upload_state.expected_hash = req.hash.value_or("");
        upload_state.bytes_received = 0;
        upload_state.part_path = *resolved;
        upload_state.part_path += ".part";

        // Otvoríme súbor pre zápis
        upload_state.file.open(upload_state.part_path, std::ios::binary | std::ios::trunc);
        if (!upload_state.file) {
            return Response::error(ErrorCode::FILE_WRITE_ERROR);
        }

        current_upload_ = std::move(upload_state);
        current_upload_remote_path_ = *req.path;

        // Registrujeme pending upload pre authenticated users
        if (authenticated_) {
            PendingUpload pending;
            pending.username = username_;
            pending.remote_path = *req.path;
            pending.part_path = current_upload_->part_path.string();
            pending.expected_size = *req.size;
            pending.expected_hash = req.hash.value_or("");
            pending.bytes_received = 0;
            resume_manager_->register_upload(username_, pending);
        }

        auto resp = Response::ok("Ready for upload");
        resp.offset = 0;
        return resp;
    }

    // CHUNK handler
    Response handle_chunk(const Request& req) {
        if (!current_upload_) {
            return Response::error(ErrorCode::INVALID_COMMAND, "No upload in progress");
        }

        if (!req.data) {
            return Response::error(ErrorCode::INVALID_ARGUMENT, "Chunk data required");
        }

        // Dekódujeme base64 dáta
        auto decoded = Base64::decode(*req.data);
        if (!decoded) {
            return Response::error(ErrorCode::INVALID_ARGUMENT, "Invalid base64 data");
        }

        // Zapíšeme do súboru
        current_upload_->file.write(
            reinterpret_cast<const char*>(decoded->data()),
            static_cast<std::streamsize>(decoded->size())
        );

        if (!current_upload_->file) {
            current_upload_->file.close();
            (void)PathUtils::remove_file(current_upload_->part_path);
            current_upload_.reset();
            return Response::error(ErrorCode::FILE_WRITE_ERROR);
        }

        // Aktualizujeme hash
        current_upload_->hasher.update(*decoded);
        current_upload_->bytes_received += decoded->size();

        spdlog::debug("[{}] CHUNK received {} bytes (total: {}/{})",
                     client_id_, decoded->size(),
                     current_upload_->bytes_received,
                     current_upload_->expected_size);

        // Kontrola či je upload kompletný
        if (current_upload_->bytes_received >= current_upload_->expected_size) {
            return finalize_upload();
        }

        auto resp = Response::ok("Chunk received");
        resp.offset = current_upload_->bytes_received;
        return resp;
    }

    // Finalizácia uploadu
    Response finalize_upload() {
        if (!current_upload_) {
            return Response::error(ErrorCode::SERVER_ERROR);
        }

        current_upload_->file.close();

        // Verifikácia hashu
        std::string actual_hash = current_upload_->hasher.finalize_hex();
        if (!current_upload_->expected_hash.empty() &&
            actual_hash != current_upload_->expected_hash) {
            (void)PathUtils::remove_file(current_upload_->part_path);
            if (authenticated_) {
                resume_manager_->cancel_upload(username_, current_upload_remote_path_);
            }
            current_upload_.reset();
            return Response::error(ErrorCode::FILE_HASH_MISMATCH);
        }

        // Presunieme .part súbor na finálne miesto
        if (!PathUtils::rename(current_upload_->part_path, current_upload_->path)) {
            (void)PathUtils::remove_file(current_upload_->part_path);
            if (authenticated_) {
                resume_manager_->cancel_upload(username_, current_upload_remote_path_);
            }
            current_upload_.reset();
            return Response::error(ErrorCode::FILE_WRITE_ERROR);
        }

        spdlog::info("[{}] Upload complete: {} ({} bytes)",
                    client_id_,
                    current_upload_->path.filename().string(),
                    current_upload_->bytes_received);

        // Odstránime z pending uploads
        if (authenticated_) {
            resume_manager_->complete_upload(username_, current_upload_remote_path_);
        }

        current_upload_.reset();
        current_upload_remote_path_.clear();

        auto resp = Response::ok("Upload complete");
        resp.hash = actual_hash;
        return resp;
    }

    // DOWNLOAD handler
    Response handle_download(const Request& req) {
        if (!req.path) {
            return Response::error(ErrorCode::INVALID_ARGUMENT, "Path required");
        }

        spdlog::debug("[{}] DOWNLOAD {}", client_id_, *req.path);

        std::optional<fs::path> resolved;
        if (authenticated_ && user_file_manager_) {
            resolved = user_file_manager_->resolve_path_safe(*req.path);
        } else {
            resolved = file_manager_->resolve_path_safe(*req.path);
        }
        
        if (!resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL_DENIED);
        }

        if (!PathUtils::exists(*resolved)) {
            return Response::error(ErrorCode::FILE_NOT_FOUND);
        }

        if (PathUtils::is_directory(*resolved)) {
            return Response::error(ErrorCode::NOT_A_FILE);
        }

        // Získame info o súbore
        auto size = PathUtils::file_size(*resolved);
        if (!size) {
            return Response::error(ErrorCode::FILE_READ_ERROR);
        }

        auto hash = HashUtils::hash_file_hex(*resolved);
        if (!hash) {
            return Response::error(ErrorCode::FILE_READ_ERROR);
        }

        // Otvoríme súbor
        std::ifstream file(*resolved, std::ios::binary);
        if (!file) {
            return Response::error(ErrorCode::FILE_READ_ERROR);
        }

        // Offset pre resume
        std::uint64_t offset = req.offset.value_or(0);
        if (offset > 0) {
            file.seekg(static_cast<std::streamoff>(offset));
            if (!file) {
                return Response::error(ErrorCode::INVALID_ARGUMENT, "Invalid offset");
            }
        }

        spdlog::info("[{}] Download started: {} ({} bytes, offset: {})",
                    client_id_, resolved->filename().string(), *size, offset);

        // Posielame súbor po chunkoch
        std::array<char, protocol::CHUNK_SIZE> buffer{};
        std::uint64_t total_sent = offset;

        // Najprv pošleme response s metadátami
        auto init_resp = Response::ok("Download starting");
        init_resp.size = *size;
        init_resp.hash = *hash;
        init_resp.offset = offset;

        auto send_result = socket_.send_message(init_resp);
        if (!send_result) {
            return Response::error(ErrorCode::CONNECTION_LOST);
        }

        // Teraz posielame chunky
        while (file && total_sent < *size) {
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

            Response chunk_resp;
            chunk_resp.code = static_cast<std::uint16_t>(ErrorCode::OK);
            chunk_resp.message = "CHUNK";
            chunk_resp.data = std::move(encoded);
            chunk_resp.offset = total_sent;

            auto chunk_send = socket_.send_message(chunk_resp);
            if (!chunk_send) {
                spdlog::error("[{}] Failed to send chunk", client_id_);
                return Response::error(ErrorCode::CONNECTION_LOST);
            }

            total_sent += bytes_read;
        }

        // Finálna správa
        Response final_resp = Response::ok("Download complete");
        final_resp.size = total_sent;
        final_resp.hash = *hash;
        return final_resp;
    }

    Socket socket_;
    std::string client_id_;
    std::shared_ptr<FileManager> file_manager_;
    std::shared_ptr<UserFileManager> user_file_manager_;  // Pre authenticated users
    std::shared_ptr<AuthManager> auth_manager_;
    std::shared_ptr<ResumeManager> resume_manager_;
    fs::path users_root_;
    fs::path public_root_;
    std::atomic<bool> running_{true};

    // Auth state
    bool authenticated_ = false;
    std::string username_;

    // Stav prebiehajúceho uploadu
    struct UploadState {
        fs::path path;
        fs::path part_path;
        std::uint64_t expected_size = 0;
        std::string expected_hash;
        std::uint64_t bytes_received = 0;
        std::ofstream file;
        HashStream hasher;
    };
    std::optional<UploadState> current_upload_;
    std::string current_upload_remote_path_;  // Pre resume tracking
};

} // namespace minidrive::server
