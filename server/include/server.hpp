#pragma once

#include "client_handler.hpp"
#include "file_manager.hpp"
#include "auth_manager.hpp"
#include "resume_manager.hpp"
#include "minidrive/minidrive.hpp"

#include <spdlog/spdlog.h>

#include <atomic>
#include <csignal>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace minidrive::server {

// Globálny flag pre signal handling
inline std::atomic<bool> g_shutdown_requested{false};

// Signal handler
inline void signal_handler(int signal) {
    if (signal == SIGTERM || signal == SIGINT) {
        spdlog::info("Shutdown signal received");
        g_shutdown_requested = true;
    }
}

// Hlavná serverová trieda
class Server {
public:
    struct Config {
        std::uint16_t port = 9000;
        std::filesystem::path root_path = "./data";
    };

    explicit Server(Config config)
        : config_(std::move(config))
    {
        // Vytvoríme root priečinok
        (void)PathUtils::create_directories(config_.root_path);

        // Vytvoríme public priečinok
        public_root_ = config_.root_path / "public";
        (void)PathUtils::create_directories(public_root_);

        // Vytvoríme priečinok pre užívateľov
        users_root_ = config_.root_path / "users";
        (void)PathUtils::create_directories(users_root_);

        // Vytvoríme auth manager
        auth_manager_ = std::make_shared<AuthManager>(users_root_);

        // Vytvoríme resume manager
        resume_manager_ = std::make_shared<ResumeManager>(config_.root_path);
    }

    ~Server() {
        stop();
    }

    // Disable copy
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // Spustenie servera
    bool start() {
        // Inicializácia libsodium
        if (!HashUtils::init()) {
            spdlog::error("Failed to initialize libsodium");
            return false;
        }

        // Vytvoríme listen socket
        auto socket_result = Socket::create_tcp();
        if (!socket_result) {
            spdlog::error("Failed to create socket: {}", strerror(socket_result.error()));
            return false;
        }
        listen_socket_ = std::move(*socket_result);

        // Nastavíme SO_REUSEADDR
        listen_socket_.set_reuse_addr(true);

        // Bind
        auto bind_result = listen_socket_.bind(config_.port);
        if (!bind_result) {
            spdlog::error("Failed to bind to port {}: {}", config_.port, strerror(bind_result.error()));
            return false;
        }

        // Listen
        auto listen_result = listen_socket_.listen();
        if (!listen_result) {
            spdlog::error("Failed to listen: {}", strerror(listen_result.error()));
            return false;
        }

        spdlog::info("Server listening on port {}", config_.port);
        spdlog::info("Root directory: {}", std::filesystem::absolute(config_.root_path).string());

        // Nastavíme signal handlers
        std::signal(SIGTERM, signal_handler);
        std::signal(SIGINT, signal_handler);

        running_ = true;

        // Spustíme accept loop
        accept_loop();

        return true;
    }

    // Zastavenie servera
    void stop() {
        if (!running_.exchange(false)) {
            return;
        }

        spdlog::info("Stopping server...");

        // Uložíme stav resume managera
        if (resume_manager_) {
            resume_manager_->save_state();
        }

        // Zatvoríme listen socket (prerušíme accept)
        listen_socket_.close();

        // Zastavíme všetky client handlers
        {
            std::lock_guard lock(clients_mutex_);
            for (auto& [id, handler] : client_handlers_) {
                handler->stop();
            }
        }

        // Počkáme na dokončenie všetkých client threads
        for (auto& thread : client_threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }

        client_threads_.clear();
        client_handlers_.clear();

        spdlog::info("Server stopped");
    }

private:
    // Accept loop
    void accept_loop() {
        while (running_ && !g_shutdown_requested) {
            auto accept_result = listen_socket_.accept();

            if (!accept_result) {
                if (!running_ || g_shutdown_requested) {
                    break;
                }
                if (accept_result.error() == EINTR) {
                    continue;
                }
                spdlog::error("Accept error: {}", strerror(accept_result.error()));
                continue;
            }

            auto [client_socket, client_ip, client_port] = std::move(*accept_result);

            // Generujeme unikátne ID pre klienta
            std::string client_id = client_ip + ":" + std::to_string(client_port) +
                                    "#" + std::to_string(next_client_id_++);

            spdlog::info("New connection from {} (id: {})", client_ip, client_id);

            // Vytvoríme file manager pre public mode (default)
            auto file_manager = std::make_shared<FileManager>(public_root_);

            // Vytvoríme handler s auth support
            auto handler = std::make_shared<ClientHandler>(
                std::move(client_socket),
                client_id,
                file_manager,
                auth_manager_,
                resume_manager_,
                users_root_,
                public_root_
            );

            // Uložíme handler
            {
                std::lock_guard lock(clients_mutex_);
                client_handlers_[client_id] = handler;
            }

            // Spustíme v novom threade - explicitný capture
            auto handler_copy = handler;
            auto client_id_copy = client_id;
            client_threads_.emplace_back([this, handler_copy, client_id_copy]() {
                handler_copy->run();

                // Odstránime handler po ukončení
                std::lock_guard lock(clients_mutex_);
                client_handlers_.erase(client_id_copy);
            });

            // Upratovanie starých threadov
            cleanup_finished_threads();
        }

        stop();
    }

    // Upratanie dokončených threadov
    void cleanup_finished_threads() {
        client_threads_.erase(
            std::remove_if(client_threads_.begin(), client_threads_.end(),
                [](std::thread& t) {
                    if (t.joinable()) {
                        // Skontrolujeme či thread skončil
                        // Toto nie je ideálne, ale pre jednoduchosť
                        return false;
                    }
                    return true;
                }
            ),
            client_threads_.end()
        );
    }

    Config config_;
    Socket listen_socket_;
    std::atomic<bool> running_{false};
    std::atomic<std::uint64_t> next_client_id_{1};

    std::filesystem::path public_root_;
    std::filesystem::path users_root_;
    std::shared_ptr<AuthManager> auth_manager_;
    std::shared_ptr<ResumeManager> resume_manager_;

    std::mutex clients_mutex_;
    std::unordered_map<std::string, std::shared_ptr<ClientHandler>> client_handlers_;
    std::vector<std::thread> client_threads_;
};

} // namespace minidrive::server
