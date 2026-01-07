#pragma once

#include "error_codes.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace minidrive {

// Typy príkazov
enum class CommandType {
    // Lokálne príkazy (spracované klientom)
    HELP,
    EXIT,

    // Súborové príkazy
    LIST,
    UPLOAD,
    DOWNLOAD,
    DELETE,

    // Priečinkové príkazy
    CD,
    MKDIR,
    RMDIR,
    MOVE,
    COPY,

    // Synchronizácia
    SYNC,
    HASH_LIST,  // Získanie zoznamu súborov s hashmi pre sync

    // Autentifikácia
    AUTH,
    REGISTER,

    // Resume
    RESUME_LIST,    // Zoznam nedokončených transferov
    RESUME_UPLOAD,  // Pokračovanie v uploade

    // Interné
    HANDSHAKE,
    CHUNK,
    CHUNK_ACK,
    RESUME_CHECK,
    DISCONNECT,
};

// Konverzia CommandType na string
inline std::string command_type_to_string(CommandType cmd) {
    switch (cmd) {
        case CommandType::HELP: return "HELP";
        case CommandType::EXIT: return "EXIT";
        case CommandType::LIST: return "LIST";
        case CommandType::UPLOAD: return "UPLOAD";
        case CommandType::DOWNLOAD: return "DOWNLOAD";
        case CommandType::DELETE: return "DELETE";
        case CommandType::CD: return "CD";
        case CommandType::MKDIR: return "MKDIR";
        case CommandType::RMDIR: return "RMDIR";
        case CommandType::MOVE: return "MOVE";
        case CommandType::COPY: return "COPY";
        case CommandType::SYNC: return "SYNC";
        case CommandType::HASH_LIST: return "HASH_LIST";
        case CommandType::AUTH: return "AUTH";
        case CommandType::REGISTER: return "REGISTER";
        case CommandType::RESUME_LIST: return "RESUME_LIST";
        case CommandType::RESUME_UPLOAD: return "RESUME_UPLOAD";
        case CommandType::HANDSHAKE: return "HANDSHAKE";
        case CommandType::CHUNK: return "CHUNK";
        case CommandType::CHUNK_ACK: return "CHUNK_ACK";
        case CommandType::RESUME_CHECK: return "RESUME_CHECK";
        case CommandType::DISCONNECT: return "DISCONNECT";
    }
    return "UNKNOWN";
}

// Konverzia string na CommandType
inline std::optional<CommandType> string_to_command_type(const std::string& str) {
    if (str == "HELP") return CommandType::HELP;
    if (str == "EXIT") return CommandType::EXIT;
    if (str == "LIST") return CommandType::LIST;
    if (str == "UPLOAD") return CommandType::UPLOAD;
    if (str == "DOWNLOAD") return CommandType::DOWNLOAD;
    if (str == "DELETE") return CommandType::DELETE;
    if (str == "CD") return CommandType::CD;
    if (str == "MKDIR") return CommandType::MKDIR;
    if (str == "RMDIR") return CommandType::RMDIR;
    if (str == "MOVE") return CommandType::MOVE;
    if (str == "COPY") return CommandType::COPY;
    if (str == "SYNC") return CommandType::SYNC;
    if (str == "HASH_LIST") return CommandType::HASH_LIST;
    if (str == "AUTH") return CommandType::AUTH;
    if (str == "REGISTER") return CommandType::REGISTER;
    if (str == "RESUME_LIST") return CommandType::RESUME_LIST;
    if (str == "RESUME_UPLOAD") return CommandType::RESUME_UPLOAD;
    if (str == "HANDSHAKE") return CommandType::HANDSHAKE;
    if (str == "CHUNK") return CommandType::CHUNK;
    if (str == "CHUNK_ACK") return CommandType::CHUNK_ACK;
    if (str == "RESUME_CHECK") return CommandType::RESUME_CHECK;
    if (str == "DISCONNECT") return CommandType::DISCONNECT;
    return std::nullopt;
}

// Štruktúra pre informácie o súbore
struct FileInfo {
    std::string name;
    bool is_directory = false;
    std::uint64_t size = 0;
    std::string hash;              // SHA-256 hash (pre súbory)
    std::int64_t modified_time = 0; // Unix timestamp

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(FileInfo, name, is_directory, size, hash, modified_time)
};

// Požiadavka od klienta
struct Request {
    std::string cmd;                           // Názov príkazu
    std::optional<std::string> path;           // Cesta (pre LIST, CD, DELETE, atď.)
    std::optional<std::string> dest;           // Cieľová cesta (pre MOVE, COPY, UPLOAD, DOWNLOAD)
    std::optional<std::string> username;       // Pre AUTH/REGISTER
    std::optional<std::string> password;       // Pre AUTH/REGISTER
    std::optional<std::uint64_t> offset;       // Pre resume/chunk operácie
    std::optional<std::uint64_t> size;         // Veľkosť súboru/chunku
    std::optional<std::string> hash;           // Hash súboru
    std::optional<std::string> data;           // Base64 encoded data pre chunky

    // Serializácia/deserializácia
    [[nodiscard]] std::string to_json() const {
        nlohmann::json j;
        j["cmd"] = cmd;
        if (path) j["path"] = *path;
        if (dest) j["dest"] = *dest;
        if (username) j["username"] = *username;
        if (password) j["password"] = *password;
        if (offset) j["offset"] = *offset;
        if (size) j["size"] = *size;
        if (hash) j["hash"] = *hash;
        if (data) j["data"] = *data;
        return j.dump();
    }

    static Request from_json(const std::string& json_str) {
        auto j = nlohmann::json::parse(json_str);
        Request req;
        req.cmd = j.at("cmd").get<std::string>();
        if (j.contains("path")) req.path = j["path"].get<std::string>();
        if (j.contains("dest")) req.dest = j["dest"].get<std::string>();
        if (j.contains("username")) req.username = j["username"].get<std::string>();
        if (j.contains("password")) req.password = j["password"].get<std::string>();
        if (j.contains("offset")) req.offset = j["offset"].get<std::uint64_t>();
        if (j.contains("size")) req.size = j["size"].get<std::uint64_t>();
        if (j.contains("hash")) req.hash = j["hash"].get<std::string>();
        if (j.contains("data")) req.data = j["data"].get<std::string>();
        return req;
    }
};

// Odpoveď od servera
struct Response {
    std::uint16_t code = 0;                     // Error code
    std::string message;                        // Hlavná správa
    std::optional<std::vector<FileInfo>> files; // Pre LIST
    std::optional<std::string> current_path;    // Pre CD, aktuálna cesta
    std::optional<std::uint64_t> offset;        // Pre resume operácie
    std::optional<std::uint64_t> size;          // Veľkosť súboru
    std::optional<std::string> hash;            // Hash súboru
    std::optional<std::string> data;            // Base64 encoded data

    // Pomocné metódy
    [[nodiscard]] bool is_ok() const noexcept {
        return code == static_cast<std::uint16_t>(ErrorCode::OK);
    }

    [[nodiscard]] ErrorCode error_code() const noexcept {
        return static_cast<ErrorCode>(code);
    }

    // Factory metódy
    static Response ok(std::string msg = "OK") {
        Response resp;
        resp.code = static_cast<std::uint16_t>(ErrorCode::OK);
        resp.message = std::move(msg);
        return resp;
    }

    static Response error(ErrorCode ec, std::string msg = "") {
        Response resp;
        resp.code = static_cast<std::uint16_t>(ec);
        resp.message = msg.empty() ? std::string(error_code_to_string(ec)) : std::move(msg);
        return resp;
    }

    // Serializácia/deserializácia
    [[nodiscard]] std::string to_json() const {
        nlohmann::json j;
        j["code"] = code;
        j["message"] = message;
        if (files) {
            j["files"] = nlohmann::json::array();
            for (const auto& f : *files) {
                j["files"].push_back(nlohmann::json{
                    {"name", f.name},
                    {"is_directory", f.is_directory},
                    {"size", f.size},
                    {"hash", f.hash},
                    {"modified_time", f.modified_time}
                });
            }
        }
        if (current_path) j["current_path"] = *current_path;
        if (offset) j["offset"] = *offset;
        if (size) j["size"] = *size;
        if (hash) j["hash"] = *hash;
        if (data) j["data"] = *data;
        return j.dump();
    }

    static Response from_json(const std::string& json_str) {
        auto j = nlohmann::json::parse(json_str);
        Response resp;
        resp.code = j.at("code").get<std::uint16_t>();
        resp.message = j.at("message").get<std::string>();
        if (j.contains("files")) {
            resp.files = std::vector<FileInfo>{};
            for (const auto& f : j["files"]) {
                FileInfo fi;
                fi.name = f.at("name").get<std::string>();
                fi.is_directory = f.at("is_directory").get<bool>();
                fi.size = f.at("size").get<std::uint64_t>();
                fi.hash = f.value("hash", "");
                fi.modified_time = f.value("modified_time", 0);
                resp.files->push_back(std::move(fi));
            }
        }
        if (j.contains("current_path")) resp.current_path = j["current_path"].get<std::string>();
        if (j.contains("offset")) resp.offset = j["offset"].get<std::uint64_t>();
        if (j.contains("size")) resp.size = j["size"].get<std::uint64_t>();
        if (j.contains("hash")) resp.hash = j["hash"].get<std::string>();
        if (j.contains("data")) resp.data = j["data"].get<std::string>();
        return resp;
    }
};

// Konštanty protokolu
namespace protocol {
    // Veľkosť chunku pre prenos súborov (64 KB)
    inline constexpr std::size_t CHUNK_SIZE = 64 * 1024;

    // Maximálna veľkosť súboru (4 GB)
    inline constexpr std::uint64_t MAX_FILE_SIZE = 4ULL * 1024 * 1024 * 1024;

    // Timeout pre neaktívne spojenie (sekúnd)
    inline constexpr int CONNECTION_TIMEOUT = 300;

    // Timeout pre resume (hodín)
    inline constexpr int RESUME_TIMEOUT_HOURS = 1;

    // Delimiter pre správy (newline)
    inline constexpr char MESSAGE_DELIMITER = '\n';

    // Verzia protokolu
    inline constexpr std::string_view PROTOCOL_VERSION = "1.0";
}

} // namespace minidrive
