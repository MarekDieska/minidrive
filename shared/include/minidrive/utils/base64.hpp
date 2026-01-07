#pragma once

#include <sodium.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace minidrive {

// Base64 encoding/decoding pomocou libsodium
class Base64 {
public:
    // Encode binary data to base64 string
    [[nodiscard]] static std::string encode(std::span<const std::uint8_t> data) {
        if (data.empty()) {
            return {};
        }

        // Vypočítame potrebnú veľkosť
        std::size_t encoded_len = sodium_base64_encoded_len(
            data.size(),
            sodium_base64_VARIANT_ORIGINAL
        );

        std::string result(encoded_len, '\0');

        sodium_bin2base64(
            result.data(),
            result.size(),
            data.data(),
            data.size(),
            sodium_base64_VARIANT_ORIGINAL
        );

        // Odstránime trailing null
        while (!result.empty() && result.back() == '\0') {
            result.pop_back();
        }

        return result;
    }

    // Encode string to base64
    [[nodiscard]] static std::string encode(std::string_view str) {
        return encode(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(str.data()),
            str.size()
        ));
    }

    // Decode base64 string to binary data
    [[nodiscard]] static std::optional<std::vector<std::uint8_t>> decode(std::string_view encoded) {
        if (encoded.empty()) {
            return std::vector<std::uint8_t>{};
        }

        // Maximálna veľkosť dekódovaných dát
        std::size_t max_decoded_len = encoded.size() * 3 / 4 + 1;
        std::vector<std::uint8_t> result(max_decoded_len);
        std::size_t actual_len = 0;

        int ret = sodium_base642bin(
            result.data(),
            result.size(),
            encoded.data(),
            encoded.size(),
            nullptr,  // ignore chars
            &actual_len,
            nullptr,  // end pointer
            sodium_base64_VARIANT_ORIGINAL
        );

        if (ret != 0) {
            return std::nullopt;
        }

        result.resize(actual_len);
        return result;
    }

    // Decode base64 to string
    [[nodiscard]] static std::optional<std::string> decode_to_string(std::string_view encoded) {
        auto decoded = decode(encoded);
        if (!decoded) {
            return std::nullopt;
        }
        return std::string(
            reinterpret_cast<const char*>(decoded->data()),
            decoded->size()
        );
    }
};

} // namespace minidrive
