#pragma once

#include <sodium.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <optional>
#include <span>
#include <sstream>
#include <string>

namespace minidrive {

// Utility trieda pre hashovanie (používa libsodium)
class HashUtils {
public:
    // Veľkosť SHA-256 hashu v bytoch
    static constexpr std::size_t HASH_SIZE = crypto_hash_sha256_BYTES; // 32 bytes

    // Typ pre raw hash
    using HashBytes = std::array<std::uint8_t, HASH_SIZE>;

    // Inicializácia libsodium (musí byť volaná pred použitím)
    [[nodiscard]] static bool init() noexcept {
        static bool initialized = false;
        if (!initialized) {
            if (sodium_init() < 0) {
                return false;
            }
            initialized = true;
        }
        return true;
    }

    // Hash dát v pamäti
    [[nodiscard]] static HashBytes hash_data(std::span<const std::uint8_t> data) noexcept {
        HashBytes result{};
        crypto_hash_sha256(result.data(), data.data(), data.size());
        return result;
    }

    // Hash stringu
    [[nodiscard]] static HashBytes hash_string(std::string_view str) noexcept {
        return hash_data(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(str.data()),
            str.size()
        ));
    }

    // Hash súboru - streamovaný pre veľké súbory
    [[nodiscard]] static std::optional<HashBytes> hash_file(const std::filesystem::path& path) noexcept {
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            return std::nullopt;
        }

        crypto_hash_sha256_state state;
        crypto_hash_sha256_init(&state);

        constexpr std::size_t BUFFER_SIZE = 64 * 1024; // 64 KB buffer
        std::array<std::uint8_t, BUFFER_SIZE> buffer{};

        while (file) {
            file.read(reinterpret_cast<char*>(buffer.data()),
                     static_cast<std::streamsize>(buffer.size()));
            auto bytes_read = static_cast<std::size_t>(file.gcount());
            if (bytes_read > 0) {
                crypto_hash_sha256_update(&state, buffer.data(), bytes_read);
            }
        }

        HashBytes result{};
        crypto_hash_sha256_final(&state, result.data());
        return result;
    }

    // Konverzia hash na hex string
    [[nodiscard]] static std::string to_hex(const HashBytes& hash) noexcept {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (auto byte : hash) {
            oss << std::setw(2) << static_cast<unsigned>(byte);
        }
        return oss.str();
    }

    // Konverzia hex string na hash
    [[nodiscard]] static std::optional<HashBytes> from_hex(std::string_view hex) noexcept {
        if (hex.size() != HASH_SIZE * 2) {
            return std::nullopt;
        }

        HashBytes result{};
        for (std::size_t i = 0; i < HASH_SIZE; ++i) {
            auto byte_str = hex.substr(i * 2, 2);
            char* end = nullptr;
            auto value = std::strtoul(std::string(byte_str).c_str(), &end, 16);
            if (*end != '\0' || value > 255) {
                return std::nullopt;
            }
            result[i] = static_cast<std::uint8_t>(value);
        }
        return result;
    }

    // Hash súboru a vráť ako hex string
    [[nodiscard]] static std::optional<std::string> hash_file_hex(
        const std::filesystem::path& path
    ) noexcept {
        auto hash = hash_file(path);
        if (!hash) {
            return std::nullopt;
        }
        return to_hex(*hash);
    }

    // Porovnanie dvoch hashov (constant time)
    [[nodiscard]] static bool compare(const HashBytes& a, const HashBytes& b) noexcept {
        return sodium_memcmp(a.data(), b.data(), HASH_SIZE) == 0;
    }

    // Porovnanie hashu s hex stringom
    [[nodiscard]] static bool compare_hex(const HashBytes& hash, std::string_view hex) noexcept {
        auto other = from_hex(hex);
        if (!other) {
            return false;
        }
        return compare(hash, *other);
    }
};

// Trieda pre streamované hashovanie (pre chunked upload/download)
class HashStream {
public:
    HashStream() {
        crypto_hash_sha256_init(&state_);
    }

    // Pridanie dát do hashu
    void update(std::span<const std::uint8_t> data) noexcept {
        crypto_hash_sha256_update(&state_, data.data(), data.size());
        total_bytes_ += data.size();
    }

    void update(std::string_view str) noexcept {
        update(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(str.data()),
            str.size()
        ));
    }

    // Finalizácia a získanie hashu
    [[nodiscard]] HashUtils::HashBytes finalize() noexcept {
        HashUtils::HashBytes result{};
        crypto_hash_sha256_final(&state_, result.data());
        return result;
    }

    // Finalizácia a získanie hex stringu
    [[nodiscard]] std::string finalize_hex() noexcept {
        return HashUtils::to_hex(finalize());
    }

    // Získanie celkového počtu spracovaných bytov
    [[nodiscard]] std::size_t total_bytes() const noexcept {
        return total_bytes_;
    }

private:
    crypto_hash_sha256_state state_{};
    std::size_t total_bytes_ = 0;
};

} // namespace minidrive
