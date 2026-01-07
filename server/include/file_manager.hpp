#pragma once

#include "minidrive/minidrive.hpp"

#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace minidrive::server {

namespace fs = std::filesystem;

// Správca súborov pre jedného užívateľa/session
// Thread-safe pre operácie s rovnakou session
class FileManager {
public:
    explicit FileManager(fs::path root_path)
        : root_(std::move(root_path))
        , current_path_(root_)
    {
        // Vytvoríme root ak neexistuje
        (void)PathUtils::create_directories(root_);
    }

    // Získanie root cesty
    [[nodiscard]] const fs::path& root() const noexcept {
        return root_;
    }

    // Získanie aktuálnej cesty
    [[nodiscard]] fs::path current_path() const {
        std::lock_guard lock(mutex_);
        return current_path_;
    }

    // Získanie relatívnej aktuálnej cesty (voči root)
    [[nodiscard]] std::string current_relative_path() const {
        std::lock_guard lock(mutex_);
        auto rel = PathUtils::get_relative(root_, current_path_);
        if (!rel || rel->empty()) {
            return "/";
        }
        return "/" + rel->string();
    }

    // Zmena aktuálneho priečinka
    [[nodiscard]] Response change_directory(std::string_view path) {
        std::lock_guard lock(mutex_);

        auto resolved = resolve_path(path);
        if (!resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL_DENIED);
        }

        if (!PathUtils::is_directory(*resolved)) {
            if (PathUtils::exists(*resolved)) {
                return Response::error(ErrorCode::NOT_A_DIRECTORY);
            }
            return Response::error(ErrorCode::DIRECTORY_NOT_FOUND);
        }

        current_path_ = *resolved;

        auto resp = Response::ok();
        resp.current_path = current_relative_path_unlocked();
        return resp;
    }

    // LIST - výpis súborov
    [[nodiscard]] Response list_directory(std::string_view path = "") {
        std::lock_guard lock(mutex_);

        fs::path target = current_path_;
        if (!path.empty()) {
            auto resolved = resolve_path(path);
            if (!resolved) {
                return Response::error(ErrorCode::PATH_TRAVERSAL_DENIED);
            }
            target = *resolved;
        }

        if (!PathUtils::is_directory(target)) {
            if (PathUtils::exists(target)) {
                return Response::error(ErrorCode::NOT_A_DIRECTORY);
            }
            return Response::error(ErrorCode::DIRECTORY_NOT_FOUND);
        }

        std::vector<FileInfo> files;
        std::error_code ec;

        for (const auto& entry : fs::directory_iterator(target, ec)) {
            if (ec) continue;

            FileInfo info;
            info.name = entry.path().filename().string();
            info.is_directory = entry.is_directory(ec);

            if (!info.is_directory && !ec) {
                info.size = entry.file_size(ec);
                if (!ec) {
                    // Hash len pre menšie súbory (optimalizácia)
                    if (info.size < 100 * 1024 * 1024) { // < 100MB
                        auto hash = HashUtils::hash_file_hex(entry.path());
                        if (hash) {
                            info.hash = *hash;
                        }
                    }
                }
            }

            auto mtime = PathUtils::last_modified(entry.path());
            if (mtime) {
                info.modified_time = *mtime;
            }

            files.push_back(std::move(info));
        }

        auto resp = Response::ok();
        resp.files = std::move(files);
        resp.current_path = current_relative_path_unlocked();
        return resp;
    }

    // MKDIR - vytvorenie priečinka
    [[nodiscard]] Response make_directory(std::string_view path) {
        std::lock_guard lock(mutex_);

        auto resolved = resolve_path(path);
        if (!resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL_DENIED);
        }

        if (PathUtils::exists(*resolved)) {
            return Response::error(ErrorCode::DIRECTORY_ALREADY_EXISTS);
        }

        if (!PathUtils::create_directories(*resolved)) {
            return Response::error(ErrorCode::PERMISSION_DENIED);
        }

        return Response::ok("Directory created");
    }

    // RMDIR - odstránenie priečinka (rekurzívne)
    [[nodiscard]] Response remove_directory(std::string_view path) {
        std::lock_guard lock(mutex_);

        auto resolved = resolve_path(path);
        if (!resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL_DENIED);
        }

        if (!PathUtils::exists(*resolved)) {
            return Response::error(ErrorCode::DIRECTORY_NOT_FOUND);
        }

        if (!PathUtils::is_directory(*resolved)) {
            return Response::error(ErrorCode::NOT_A_DIRECTORY);
        }

        // Nesmieme mazať aktuálny priečinok alebo jeho rodičov
        std::error_code ec;
        if (fs::equivalent(*resolved, current_path_, ec) || !ec) {
            // Skontrolujeme či current_path je pod resolved
            auto rel = fs::relative(current_path_, *resolved, ec);
            if (!ec && !rel.empty() && rel.begin()->string() != "..") {
                current_path_ = resolved->parent_path();
                if (!is_under_root(current_path_)) {
                    current_path_ = root_;
                }
            }
        }

        auto removed = PathUtils::remove_all(*resolved);
        if (removed == 0) {
            return Response::error(ErrorCode::PERMISSION_DENIED);
        }

        return Response::ok("Directory removed");
    }

    // DELETE - odstránenie súboru
    [[nodiscard]] Response delete_file(std::string_view path) {
        std::lock_guard lock(mutex_);

        auto resolved = resolve_path(path);
        if (!resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL_DENIED);
        }

        if (!PathUtils::exists(*resolved)) {
            return Response::error(ErrorCode::FILE_NOT_FOUND);
        }

        if (PathUtils::is_directory(*resolved)) {
            return Response::error(ErrorCode::NOT_A_FILE);
        }

        if (!PathUtils::remove_file(*resolved)) {
            return Response::error(ErrorCode::PERMISSION_DENIED);
        }

        return Response::ok("File deleted");
    }

    // MOVE - presun/premenovanie
    [[nodiscard]] Response move(std::string_view src, std::string_view dst) {
        std::lock_guard lock(mutex_);

        auto src_resolved = resolve_path(src);
        auto dst_resolved = resolve_path(dst);

        if (!src_resolved || !dst_resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL_DENIED);
        }

        if (!PathUtils::exists(*src_resolved)) {
            return Response::error(ErrorCode::FILE_NOT_FOUND);
        }

        if (PathUtils::exists(*dst_resolved)) {
            return Response::error(ErrorCode::FILE_ALREADY_EXISTS);
        }

        // Vytvoríme parent directory ak neexistuje
        (void)PathUtils::create_directories(dst_resolved->parent_path());

        if (!PathUtils::rename(*src_resolved, *dst_resolved)) {
            return Response::error(ErrorCode::PERMISSION_DENIED);
        }

        return Response::ok("Moved successfully");
    }

    // COPY - kopírovanie
    [[nodiscard]] Response copy(std::string_view src, std::string_view dst) {
        std::lock_guard lock(mutex_);

        auto src_resolved = resolve_path(src);
        auto dst_resolved = resolve_path(dst);

        if (!src_resolved || !dst_resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL_DENIED);
        }

        if (!PathUtils::exists(*src_resolved)) {
            return Response::error(ErrorCode::FILE_NOT_FOUND);
        }

        if (PathUtils::exists(*dst_resolved)) {
            return Response::error(ErrorCode::FILE_ALREADY_EXISTS);
        }

        // Vytvoríme parent directory ak neexistuje
        (void)PathUtils::create_directories(dst_resolved->parent_path());

        bool success = false;
        if (PathUtils::is_directory(*src_resolved)) {
            success = PathUtils::copy_recursive(*src_resolved, *dst_resolved);
        } else {
            success = PathUtils::copy_file(*src_resolved, *dst_resolved);
        }

        if (!success) {
            return Response::error(ErrorCode::PERMISSION_DENIED);
        }

        return Response::ok("Copied successfully");
    }

    // Získanie plnej cesty pre súbor (pre upload/download)
    [[nodiscard]] std::optional<fs::path> resolve_path(std::string_view path) const {
        // Ak je cesta prázdna, vrátime aktuálnu
        if (path.empty()) {
            return current_path_;
        }

        // Ak začína s /, je to absolútna cesta voči root
        if (path[0] == '/') {
            return PathUtils::safe_join(root_, path);
        }

        // Inak je relatívna voči current_path
        return PathUtils::safe_join(current_path_, path);
    }

    // Verejná verzia resolve_path (thread-safe)
    [[nodiscard]] std::optional<fs::path> resolve_path_safe(std::string_view path) {
        std::lock_guard lock(mutex_);
        return resolve_path(path);
    }

    // Kontrola či súbor existuje
    [[nodiscard]] bool file_exists(std::string_view path) {
        std::lock_guard lock(mutex_);
        auto resolved = resolve_path(path);
        return resolved && PathUtils::is_file(*resolved);
    }

    // Získanie informácií o súbore
    [[nodiscard]] std::optional<FileInfo> get_file_info(std::string_view path) {
        std::lock_guard lock(mutex_);
        auto resolved = resolve_path(path);
        if (!resolved || !PathUtils::exists(*resolved)) {
            return std::nullopt;
        }

        FileInfo info;
        info.name = resolved->filename().string();
        info.is_directory = PathUtils::is_directory(*resolved);

        if (!info.is_directory) {
            auto size = PathUtils::file_size(*resolved);
            if (size) {
                info.size = *size;
            }
            auto hash = HashUtils::hash_file_hex(*resolved);
            if (hash) {
                info.hash = *hash;
            }
        }

        auto mtime = PathUtils::last_modified(*resolved);
        if (mtime) {
            info.modified_time = *mtime;
        }

        return info;
    }

    // HASH_LIST - rekurzívny zoznam súborov s hashmi (pre SYNC)
    [[nodiscard]] Response hash_list(std::string_view path = "") {
        std::lock_guard lock(mutex_);

        fs::path target = current_path_;
        if (!path.empty()) {
            auto resolved = resolve_path(path);
            if (!resolved) {
                return Response::error(ErrorCode::PATH_TRAVERSAL_DENIED);
            }
            target = *resolved;
        }

        if (!PathUtils::is_directory(target)) {
            if (PathUtils::exists(target)) {
                return Response::error(ErrorCode::NOT_A_DIRECTORY);
            }
            return Response::error(ErrorCode::DIRECTORY_NOT_FOUND);
        }

        std::vector<FileInfo> files;
        collect_files_recursive(target, "", files);

        auto resp = Response::ok();
        resp.files = std::move(files);
        return resp;
    }

private:
    // Rekurzívne zbieranie súborov s hashmi
    void collect_files_recursive(const fs::path& dir, const std::string& prefix, 
                                  std::vector<FileInfo>& files) const {
        std::error_code ec;
        for (const auto& entry : fs::directory_iterator(dir, ec)) {
            if (ec) continue;

            std::string name = prefix.empty() 
                ? entry.path().filename().string() 
                : prefix + "/" + entry.path().filename().string();

            if (entry.is_directory(ec)) {
                collect_files_recursive(entry.path(), name, files);
            } else if (entry.is_regular_file(ec)) {
                FileInfo info;
                info.name = name;
                info.is_directory = false;
                info.size = entry.file_size(ec);
                
                auto hash = HashUtils::hash_file_hex(entry.path());
                if (hash) {
                    info.hash = *hash;
                }
                
                auto mtime = PathUtils::last_modified(entry.path());
                if (mtime) {
                    info.modified_time = *mtime;
                }
                
                files.push_back(std::move(info));
            }
        }
    }

    // Kontrola či cesta je pod root (bez locku)
    [[nodiscard]] bool is_under_root(const fs::path& path) const {
        std::error_code ec;
        auto canonical_root = fs::weakly_canonical(root_, ec);
        if (ec) return false;

        auto canonical_path = fs::weakly_canonical(path, ec);
        if (ec) return false;

        auto root_str = canonical_root.string();
        auto path_str = canonical_path.string();

        if (!root_str.empty() && root_str.back() != '/') {
            root_str += '/';
        }

        return path_str == canonical_root.string() ||
               path_str.find(root_str) == 0;
    }

    // Získanie relatívnej cesty bez locku (pre interné použitie)
    [[nodiscard]] std::string current_relative_path_unlocked() const {
        auto rel = PathUtils::get_relative(root_, current_path_);
        if (!rel || rel->empty()) {
            return "/";
        }
        return "/" + rel->string();
    }

    fs::path root_;
    fs::path current_path_;
    mutable std::mutex mutex_;
};

} // namespace minidrive::server
