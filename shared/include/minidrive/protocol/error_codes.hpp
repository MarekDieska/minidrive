#pragma once

#include <cstdint>
#include <string_view>

namespace minidrive {

// Error codes pre MiniDrive protokol
// Rozsahy:
//   0       = OK (žiadna chyba)
//   1-99    = Všeobecné chyby
//   100-199 = Chyby súborov
//   200-299 = Chyby priečinkov
//   300-399 = Chyby autentifikácie
//   400-499 = Chyby prenosu
//   500-599 = Serverové chyby

enum class ErrorCode : std::uint16_t {
    // Úspech
    OK = 0,

    // Všeobecné chyby (1-99)
    UNKNOWN_ERROR = 1,
    INVALID_COMMAND = 2,
    INVALID_ARGUMENT = 3,
    PERMISSION_DENIED = 4,
    PATH_TRAVERSAL_DENIED = 5,
    CONNECTION_LOST = 6,
    TIMEOUT = 7,
    INVALID_PATH = 8,

    // Chyby súborov (100-199)
    FILE_NOT_FOUND = 100,
    FILE_ALREADY_EXISTS = 101,
    FILE_TOO_LARGE = 102,
    FILE_READ_ERROR = 103,
    FILE_WRITE_ERROR = 104,
    FILE_HASH_MISMATCH = 105,
    FILE_BUSY = 106,

    // Chyby priečinkov (200-299)
    DIRECTORY_NOT_FOUND = 200,
    DIRECTORY_ALREADY_EXISTS = 201,
    DIRECTORY_NOT_EMPTY = 202,
    NOT_A_DIRECTORY = 203,
    NOT_A_FILE = 204,

    // Chyby autentifikácie (300-399)
    AUTH_REQUIRED = 300,
    AUTH_FAILED = 301,
    USER_NOT_FOUND = 302,
    USER_ALREADY_EXISTS = 303,
    SESSION_EXPIRED = 304,
    SESSION_ALREADY_ACTIVE = 305,

    // Chyby prenosu (400-499)
    TRANSFER_INCOMPLETE = 400,
    TRANSFER_CANCELLED = 401,
    TRANSFER_RESUME_FAILED = 402,
    CHUNK_ERROR = 403,

    // Serverové chyby (500-599)
    SERVER_ERROR = 500,
    SERVER_BUSY = 501,
    SERVER_SHUTTING_DOWN = 502,
};

// Konverzia error kódu na čitateľný reťazec
constexpr std::string_view error_code_to_string(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::OK: return "OK";
        case ErrorCode::UNKNOWN_ERROR: return "Unknown error";
        case ErrorCode::INVALID_COMMAND: return "Invalid command";
        case ErrorCode::INVALID_ARGUMENT: return "Invalid argument";
        case ErrorCode::PERMISSION_DENIED: return "Permission denied";
        case ErrorCode::PATH_TRAVERSAL_DENIED: return "Path traversal not allowed";
        case ErrorCode::CONNECTION_LOST: return "Connection lost";
        case ErrorCode::TIMEOUT: return "Operation timed out";
        case ErrorCode::INVALID_PATH: return "Invalid path";

        case ErrorCode::FILE_NOT_FOUND: return "File not found";
        case ErrorCode::FILE_ALREADY_EXISTS: return "File already exists";
        case ErrorCode::FILE_TOO_LARGE: return "File too large";
        case ErrorCode::FILE_READ_ERROR: return "File read error";
        case ErrorCode::FILE_WRITE_ERROR: return "File write error";
        case ErrorCode::FILE_HASH_MISMATCH: return "File hash mismatch";
        case ErrorCode::FILE_BUSY: return "File is busy";

        case ErrorCode::DIRECTORY_NOT_FOUND: return "Directory not found";
        case ErrorCode::DIRECTORY_ALREADY_EXISTS: return "Directory already exists";
        case ErrorCode::DIRECTORY_NOT_EMPTY: return "Directory not empty";
        case ErrorCode::NOT_A_DIRECTORY: return "Not a directory";
        case ErrorCode::NOT_A_FILE: return "Not a file";

        case ErrorCode::AUTH_REQUIRED: return "Authentication required";
        case ErrorCode::AUTH_FAILED: return "Authentication failed";
        case ErrorCode::USER_NOT_FOUND: return "User not found";
        case ErrorCode::USER_ALREADY_EXISTS: return "User already exists";
        case ErrorCode::SESSION_EXPIRED: return "Session expired";
        case ErrorCode::SESSION_ALREADY_ACTIVE: return "Session already active";

        case ErrorCode::TRANSFER_INCOMPLETE: return "Transfer incomplete";
        case ErrorCode::TRANSFER_CANCELLED: return "Transfer cancelled";
        case ErrorCode::TRANSFER_RESUME_FAILED: return "Transfer resume failed";
        case ErrorCode::CHUNK_ERROR: return "Chunk error";

        case ErrorCode::SERVER_ERROR: return "Server error";
        case ErrorCode::SERVER_BUSY: return "Server busy";
        case ErrorCode::SERVER_SHUTTING_DOWN: return "Server shutting down";
    }
    return "Unknown error code";
}

// Overenie či je kód úspešný
constexpr bool is_success(ErrorCode code) noexcept {
    return code == ErrorCode::OK;
}

// Overenie či je kód chybový
constexpr bool is_error(ErrorCode code) noexcept {
    return code != ErrorCode::OK;
}

} // namespace minidrive
