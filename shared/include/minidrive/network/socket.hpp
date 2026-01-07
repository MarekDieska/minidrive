#pragma once

#include "../protocol/message.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace minidrive {

class Socket {
public:
    explicit Socket(int fd = -1) noexcept : fd_(fd) {}

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    Socket(Socket&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}

    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            close();
            fd_ = std::exchange(other.fd_, -1);
        }
        return *this;
    }

    ~Socket() { close(); }

    void close() noexcept {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    [[nodiscard]] bool is_valid() const noexcept { return fd_ >= 0; }
    [[nodiscard]] explicit operator bool() const noexcept { return is_valid(); }
    [[nodiscard]] int fd() const noexcept { return fd_; }
    [[nodiscard]] int release() noexcept { return std::exchange(fd_, -1); }

    [[nodiscard]] std::expected<std::size_t, int> send(std::span<const std::byte> data) const {
        if (!is_valid()) return std::unexpected(EBADF);

        std::size_t total_sent = 0;
        while (total_sent < data.size()) {
            ssize_t sent = ::send(fd_, data.data() + total_sent,
                                  data.size() - total_sent, MSG_NOSIGNAL);
            if (sent < 0) {
                if (errno == EINTR) continue;
                return std::unexpected(errno);
            }
            if (sent == 0) return std::unexpected(ECONNRESET);
            total_sent += static_cast<std::size_t>(sent);
        }
        return total_sent;
    }

    [[nodiscard]] std::expected<std::size_t, int> send(std::string_view data) const {
        return send(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(data.data()), data.size()));
    }

    [[nodiscard]] std::expected<std::size_t, int> recv(std::span<std::byte> buffer) const {
        if (!is_valid()) return std::unexpected(EBADF);

        ssize_t received = ::recv(fd_, buffer.data(), buffer.size(), 0);
        if (received < 0) {
            if (errno == EINTR) return recv(buffer);
            return std::unexpected(errno);
        }
        return static_cast<std::size_t>(received);
    }

    [[nodiscard]] std::expected<std::string, int> recv_string(std::size_t max_size) const {
        std::string buffer(max_size, '\0');
        auto result = recv(std::span<std::byte>(
            reinterpret_cast<std::byte*>(buffer.data()), buffer.size()));
        if (!result) return std::unexpected(result.error());
        buffer.resize(*result);
        return buffer;
    }

    [[nodiscard]] std::expected<void, int> send_message(const Request& req) const {
        std::string json = req.to_json() + protocol::MESSAGE_DELIMITER;
        auto result = send(json);
        if (!result) return std::unexpected(result.error());
        return {};
    }

    [[nodiscard]] std::expected<void, int> send_message(const Response& resp) const {
        std::string json = resp.to_json() + protocol::MESSAGE_DELIMITER;
        auto result = send(json);
        if (!result) return std::unexpected(result.error());
        return {};
    }

    [[nodiscard]] std::expected<std::string, int> recv_message() {
        auto pos = recv_buffer_.find(protocol::MESSAGE_DELIMITER);
        if (pos != std::string::npos) {
            std::string message = recv_buffer_.substr(0, pos);
            recv_buffer_.erase(0, pos + 1);
            return message;
        }

        std::array<char, 8192> temp{};
        while (true) {
            auto result = recv(std::span<std::byte>(
                reinterpret_cast<std::byte*>(temp.data()), temp.size()));

            if (!result) return std::unexpected(result.error());
            if (*result == 0) {
                if (!recv_buffer_.empty()) {
                    std::string msg = std::move(recv_buffer_);
                    recv_buffer_.clear();
                    return msg;
                }
                return std::unexpected(ECONNRESET);
            }

            recv_buffer_.append(temp.data(), *result);

            pos = recv_buffer_.find(protocol::MESSAGE_DELIMITER);
            if (pos != std::string::npos) {
                std::string message = recv_buffer_.substr(0, pos);
                recv_buffer_.erase(0, pos + 1);
                return message;
            }

            if (recv_buffer_.size() > 10 * 1024 * 1024) {
                recv_buffer_.clear();
                return std::unexpected(EMSGSIZE);
            }
        }
    }

    bool set_recv_timeout(int seconds) const {
        timeval tv{.tv_sec = seconds, .tv_usec = 0};
        return ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
    }

    bool set_send_timeout(int seconds) const {
        timeval tv{.tv_sec = seconds, .tv_usec = 0};
        return ::setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
    }

    [[nodiscard]] static std::expected<Socket, int> create_tcp() {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return std::unexpected(errno);
        return Socket(fd);
    }

    [[nodiscard]] std::expected<void, int> connect(std::string_view host, std::uint16_t port) const {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (::inet_pton(AF_INET, std::string(host).c_str(), &addr.sin_addr) != 1)
            return std::unexpected(EINVAL);
        if (::connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
            return std::unexpected(errno);
        return {};
    }

    bool set_reuse_addr(bool enable = true) const {
        int opt = enable ? 1 : 0;
        return ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == 0;
    }

    [[nodiscard]] std::expected<void, int> bind(std::uint16_t port) const {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
            return std::unexpected(errno);
        return {};
    }

    [[nodiscard]] std::expected<void, int> listen(int backlog = SOMAXCONN) const {
        if (::listen(fd_, backlog) < 0) return std::unexpected(errno);
        return {};
    }

    using AcceptResult = std::tuple<Socket, std::string, std::uint16_t>;
    [[nodiscard]] std::expected<AcceptResult, int> accept() const {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        int client_fd = ::accept(fd_, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
        if (client_fd < 0) return std::unexpected(errno);

        char ip_buf[INET_ADDRSTRLEN]{};
        const char* ip = ::inet_ntop(AF_INET, &client_addr.sin_addr, ip_buf, sizeof(ip_buf));

        return std::make_tuple(Socket(client_fd), 
                               std::string(ip ? ip : "unknown"),
                               ntohs(client_addr.sin_port));
    }

private:
    int fd_ = -1;
    std::string recv_buffer_;
};

} // namespace minidrive
