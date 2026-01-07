#pragma once

#include "file_manager.hpp"
#include "minidrive/minidrive.hpp"

#include <filesystem>
#include <memory>
#include <mutex>
#include <string>

namespace minidrive::server {

namespace fs = std::filesystem;

// Špeciálny FileManager pre authenticated users
// Poskytuje prístup k /private (vlastné súbory) a /public (zdieľané)
class UserFileManager {
public:
    UserFileManager(fs::path private_root, fs::path public_root)
        : private_root_(std::move(private_root))
        , public_root_(std::move(public_root))
        , current_path_("/")
        , in_public_(false)
    {
        (void)PathUtils::create_directories(private_root_);
    }

    // Získanie aktuálnej relatívnej cesty
    [[nodiscard]] std::string current_relative_path() const {
        std::lock_guard lock(mutex_);
        return current_path_;
    }

    // CD - zmena priečinka
    [[nodiscard]] Response change_directory(std::string_view path) {
        std::lock_guard lock(mutex_);

        auto [new_path, is_public] = resolve_virtual_path(path);
        if (!new_path) {
            return Response::error(ErrorCode::PATH_TRAVERSAL_DENIED);
        }

        fs::path actual_root = is_public ? public_root_ : private_root_;
        fs::path full_path = actual_root / *new_path;

        if (!PathUtils::is_directory(full_path)) {
            if (PathUtils::exists(full_path)) {
                return Response::error(ErrorCode::NOT_A_DIRECTORY);
            }
            return Response::error(ErrorCode::DIRECTORY_NOT_FOUND);
        }

        // Aktualizujeme stav
        in_public_ = is_public;
        if (is_public) {
            current_path_ = "/public";
            if (!new_path->empty()) {
                current_path_ += "/" + *new_path;
            }
        } else {
            current_path_ = "/private";
            if (!new_path->empty()) {
                current_path_ += "/" + *new_path;
            }
        }

        // Špeciálny prípad pre root
        if (path == "/" || path == "") {
            current_path_ = "/";
            in_public_ = false;
        }

        auto resp = Response::ok();
        resp.current_path = current_path_;
        return resp;
    }

    // LIST - výpis súborov
    [[nodiscard]] Response list_directory(std::string_view path = "") {
        std::lock_guard lock(mutex_);

        // Špeciálny prípad pre root - zobrazíme private/ a public/
        if (current_path_ == "/" && path.empty()) {
            std::vector<FileInfo> files;
            
            FileInfo private_info;
            private_info.name = "private";
            private_info.is_directory = true;
            files.push_back(private_info);

            FileInfo public_info;
            public_info.name = "public";
            public_info.is_directory = true;
            files.push_back(public_info);

            auto resp = Response::ok();
            resp.files = std::move(files);
            resp.current_path = "/";
            return resp;
        }

        // Určíme skutočnú cestu
        auto [rel_path, is_public] = resolve_virtual_path(path);
        if (!rel_path) {
            return Response::error(ErrorCode::PATH_TRAVERSAL_DENIED);
        }

        fs::path actual_root = is_public ? public_root_ : private_root_;
        fs::path full_path = actual_root / *rel_path;

        if (!PathUtils::is_directory(full_path)) {
            if (PathUtils::exists(full_path)) {
                return Response::error(ErrorCode::NOT_A_DIRECTORY);
            }
            return Response::error(ErrorCode::DIRECTORY_NOT_FOUND);
        }

        std::vector<FileInfo> files;
        std::error_code ec;

        for (const auto& entry : fs::directory_iterator(full_path, ec)) {
            if (ec) continue;

            FileInfo info;
            info.name = entry.path().filename().string();
            info.is_directory = entry.is_directory(ec);

            if (!info.is_directory && !ec) {
                info.size = entry.file_size(ec);
                if (!ec && info.size < 100 * 1024 * 1024) {
                    auto hash = HashUtils::hash_file_hex(entry.path());
                    if (hash) {
                        info.hash = *hash;
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
        resp.current_path = current_path_;
        return resp;
    }

    // MKDIR
    [[nodiscard]] Response make_directory(std::string_view path) {
        std::lock_guard lock(mutex_);

        auto resolved = resolve_to_actual_path(path);
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

    // RMDIR
    [[nodiscard]] Response remove_directory(std::string_view path) {
        std::lock_guard lock(mutex_);

        auto resolved = resolve_to_actual_path(path);
        if (!resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL_DENIED);
        }

        if (!PathUtils::exists(*resolved)) {
            return Response::error(ErrorCode::DIRECTORY_NOT_FOUND);
        }

        if (!PathUtils::is_directory(*resolved)) {
            return Response::error(ErrorCode::NOT_A_DIRECTORY);
        }

        auto removed = PathUtils::remove_all(*resolved);
        if (removed == 0) {
            return Response::error(ErrorCode::PERMISSION_DENIED);
        }

        return Response::ok("Directory removed");
    }

    // DELETE
    [[nodiscard]] Response delete_file(std::string_view path) {
        std::lock_guard lock(mutex_);

        auto resolved = resolve_to_actual_path(path);
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

    // MOVE
    [[nodiscard]] Response move(std::string_view src, std::string_view dst) {
        std::lock_guard lock(mutex_);

        auto src_resolved = resolve_to_actual_path(src);
        auto dst_resolved = resolve_to_actual_path(dst);

        if (!src_resolved || !dst_resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL_DENIED);
        }

        if (!PathUtils::exists(*src_resolved)) {
            return Response::error(ErrorCode::FILE_NOT_FOUND);
        }

        if (PathUtils::exists(*dst_resolved)) {
            return Response::error(ErrorCode::FILE_ALREADY_EXISTS);
        }

        (void)PathUtils::create_directories(dst_resolved->parent_path());

        if (!PathUtils::rename(*src_resolved, *dst_resolved)) {
            return Response::error(ErrorCode::PERMISSION_DENIED);
        }

        return Response::ok("Moved successfully");
    }

    // COPY
    [[nodiscard]] Response copy(std::string_view src, std::string_view dst) {
        std::lock_guard lock(mutex_);

        auto src_resolved = resolve_to_actual_path(src);
        auto dst_resolved = resolve_to_actual_path(dst);

        if (!src_resolved || !dst_resolved) {
            return Response::error(ErrorCode::PATH_TRAVERSAL_DENIED);
        }

        if (!PathUtils::exists(*src_resolved)) {
            return Response::error(ErrorCode::FILE_NOT_FOUND);
        }

        if (PathUtils::exists(*dst_resolved)) {
            return Response::error(ErrorCode::FILE_ALREADY_EXISTS);
        }

        (void)PathUtils::create_directories(dst_resolved->parent_path());

        bool success = PathUtils::is_directory(*src_resolved)
            ? PathUtils::copy_recursive(*src_resolved, *dst_resolved)
            : PathUtils::copy_file(*src_resolved, *dst_resolved);

        if (!success) {
            return Response::error(ErrorCode::PERMISSION_DENIED);
        }

        return Response::ok("Copied successfully");
    }

    // Resolve path pre upload/download
    [[nodiscard]] std::optional<fs::path> resolve_path_safe(std::string_view path) {
        std::lock_guard lock(mutex_);
        return resolve_to_actual_path(path);
    }

    // HASH_LIST - rekurzívny zoznam súborov s hashmi (pre SYNC)
    [[nodiscard]] Response hash_list(std::string_view path = "") {
        std::lock_guard lock(mutex_);

        // Určíme skutočnú cestu
        auto [rel_path, is_public] = resolve_virtual_path(path);
        if (!rel_path) {
            return Response::error(ErrorCode::PATH_TRAVERSAL_DENIED);
        }

        fs::path actual_root = is_public ? public_root_ : private_root_;
        fs::path full_path = actual_root / *rel_path;

        if (!PathUtils::is_directory(full_path)) {
            if (PathUtils::exists(full_path)) {
                return Response::error(ErrorCode::NOT_A_DIRECTORY);
            }
            return Response::error(ErrorCode::DIRECTORY_NOT_FOUND);
        }

        std::vector<FileInfo> files;
        collect_files_recursive(full_path, "", files);

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
                // Rekurzívne pre podpriečinky
                collect_files_recursive(entry.path(), name, files);
            } else if (entry.is_regular_file(ec)) {
                FileInfo info;
                info.name = name;
                info.is_directory = false;
                info.size = entry.file_size(ec);
                
                // Hash súboru
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
    // Rozloží virtuálnu cestu na (relatívna_cesta, is_public)
    // Vracia cestu relatívnu k príslušnému root-u
    [[nodiscard]] std::pair<std::optional<std::string>, bool> resolve_virtual_path(std::string_view path) const {
        std::string p(path);
        
        // Ak je prázdna, použijeme aktuálnu
        if (p.empty()) {
            if (current_path_ == "/") {
                return {{""}, false};
            }
            // Extrahujeme relatívnu časť z current_path_
            if (current_path_.starts_with("/public")) {
                std::string rel = current_path_.substr(7); // skip "/public"
                if (!rel.empty() && rel[0] == '/') rel = rel.substr(1);
                return {{rel}, true};
            } else if (current_path_.starts_with("/private")) {
                std::string rel = current_path_.substr(8); // skip "/private"
                if (!rel.empty() && rel[0] == '/') rel = rel.substr(1);
                return {{rel}, false};
            }
            return {{""}, false};
        }

        // Absolútna cesta
        if (p[0] == '/') {
            if (p == "/") {
                return {{""}, false}; // root
            }
            if (p.starts_with("/public")) {
                std::string rel = p.substr(7);
                if (!rel.empty() && rel[0] == '/') rel = rel.substr(1);
                if (!PathUtils::is_safe_path(rel)) return {std::nullopt, false};
                return {{rel}, true};
            }
            if (p.starts_with("/private")) {
                std::string rel = p.substr(8);
                if (!rel.empty() && rel[0] == '/') rel = rel.substr(1);
                if (!PathUtils::is_safe_path(rel)) return {std::nullopt, false};
                return {{rel}, false};
            }
            // Neznáma absolútna cesta
            return {std::nullopt, false};
        }

        // Relatívna cesta - použijeme aktuálny kontext
        if (!PathUtils::is_safe_path(p)) {
            return {std::nullopt, false};
        }

        if (current_path_ == "/") {
            // Sme v roote - cesta musí začínať s public/ alebo private/
            if (p.starts_with("public")) {
                std::string rel = p.substr(6);
                if (!rel.empty() && rel[0] == '/') rel = rel.substr(1);
                return {{rel}, true};
            }
            if (p.starts_with("private")) {
                std::string rel = p.substr(7);
                if (!rel.empty() && rel[0] == '/') rel = rel.substr(1);
                return {{rel}, false};
            }
            return {std::nullopt, false};
        }

        // Sme v public alebo private
        auto [current_rel, is_public] = resolve_virtual_path("");
        if (!current_rel) return {std::nullopt, false};
        
        std::string combined = current_rel->empty() ? p : (*current_rel + "/" + p);
        return {{combined}, is_public};
    }

    // Resolve na skutočnú filesystem cestu
    [[nodiscard]] std::optional<fs::path> resolve_to_actual_path(std::string_view path) const {
        auto [rel_path, is_public] = resolve_virtual_path(path);
        if (!rel_path) {
            return std::nullopt;
        }

        fs::path root = is_public ? public_root_ : private_root_;
        return root / *rel_path;
    }

    fs::path private_root_;
    fs::path public_root_;
    std::string current_path_;
    bool in_public_;
    mutable std::mutex mutex_;
};

} // namespace minidrive::server
