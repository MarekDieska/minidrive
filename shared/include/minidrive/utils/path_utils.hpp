#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace minidrive {

namespace fs = std::filesystem;

// Utility trieda pre bezpečnú prácu s cestami
class PathUtils {
public:
    // Kontrola či cesta neobsahuje directory traversal
    // Vráti false ak cesta obsahuje ".." alebo sa snaží uniknúť z root
    [[nodiscard]] static bool is_safe_path(std::string_view path) noexcept {
        // Prázdna cesta je OK
        if (path.empty()) {
            return true;
        }

        // Kontrola na ".." component
        fs::path p(path);
        for (const auto& component : p) {
            if (component == "..") {
                return false;
            }
        }

        return true;
    }

    // Normalizácia cesty - odstráni duplicitné slashy, ., atď.
    // Nevyhodnocuje ".." - to musí byť zakázané predtým
    [[nodiscard]] static std::string normalize_path(std::string_view path) {
        if (path.empty()) {
            return "/";
        }

        fs::path p(path);
        fs::path result;

        for (const auto& component : p) {
            if (component == ".") {
                continue;
            }
            if (component.empty()) {
                continue;
            }
            result /= component;
        }

        std::string str = result.string();

        // Zachovanie leading slash ak bola v origináli
        if (!path.empty() && path[0] == '/' && (str.empty() || str[0] != '/')) {
            str = "/" + str;
        }

        return str.empty() ? "/" : str;
    }

    // Bezpečné spojenie root cesty s relatívnou cestou
    // Vráti nullopt ak by výsledok bol mimo root
    [[nodiscard]] static std::optional<fs::path> safe_join(
        const fs::path& root,
        std::string_view relative_path
    ) {
        // Najprv skontrolujeme bezpečnosť
        if (!is_safe_path(relative_path)) {
            return std::nullopt;
        }

        // Normalizujeme relatívnu cestu
        std::string normalized = normalize_path(relative_path);

        // Odstránime leading slash pre join
        if (!normalized.empty() && normalized[0] == '/') {
            normalized = normalized.substr(1);
        }

        // Spojíme cesty
        fs::path result = root / normalized;

        // Canonicalize root (musí existovať)
        std::error_code ec;
        fs::path canonical_root = fs::weakly_canonical(root, ec);
        if (ec) {
            return std::nullopt;
        }

        // Weakly canonical pre result (nemusí existovať)
        fs::path canonical_result = fs::weakly_canonical(result, ec);
        if (ec) {
            return std::nullopt;
        }

        // Overíme že výsledok je stále pod root
        auto root_str = canonical_root.string();
        auto result_str = canonical_result.string();

        // Pridáme trailing slash k root pre porovnanie
        if (!root_str.empty() && root_str.back() != '/') {
            root_str += '/';
        }

        // Result musí začínať s root alebo byť rovný root (bez trailing slash)
        auto canonical_root_no_slash = canonical_root.string();
        if (result_str != canonical_root_no_slash &&
            result_str.find(root_str) != 0) {
            return std::nullopt;
        }

        return result;
    }

    // Získanie relatívnej cesty voči root
    [[nodiscard]] static std::optional<fs::path> get_relative(
        const fs::path& root,
        const fs::path& full_path
    ) {
        std::error_code ec;
        fs::path rel = fs::relative(full_path, root, ec);
        if (ec) {
            return std::nullopt;
        }

        // Skontrolujeme že nezačína s ".."
        if (!rel.empty() && rel.begin()->string() == "..") {
            return std::nullopt;
        }

        return rel;
    }

    // Kontrola či cesta existuje a je priečinok
    [[nodiscard]] static bool is_directory(const fs::path& path) noexcept {
        std::error_code ec;
        return fs::is_directory(path, ec);
    }

    // Kontrola či cesta existuje a je súbor
    [[nodiscard]] static bool is_file(const fs::path& path) noexcept {
        std::error_code ec;
        return fs::is_regular_file(path, ec);
    }

    // Kontrola či cesta existuje
    [[nodiscard]] static bool exists(const fs::path& path) noexcept {
        std::error_code ec;
        return fs::exists(path, ec);
    }

    // Získanie veľkosti súboru
    [[nodiscard]] static std::optional<std::uintmax_t> file_size(const fs::path& path) noexcept {
        std::error_code ec;
        auto size = fs::file_size(path, ec);
        if (ec) {
            return std::nullopt;
        }
        return size;
    }

    // Získanie času poslednej modifikácie ako Unix timestamp
    [[nodiscard]] static std::optional<std::int64_t> last_modified(const fs::path& path) noexcept {
        std::error_code ec;
        auto ftime = fs::last_write_time(path, ec);
        if (ec) {
            return std::nullopt;
        }

        // Konverzia na system_clock
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
        );
        return std::chrono::duration_cast<std::chrono::seconds>(
            sctp.time_since_epoch()
        ).count();
    }

    // Vytvorenie priečinka (vrátane rodičovských)
    [[nodiscard]] static bool create_directories(const fs::path& path) noexcept {
        std::error_code ec;
        fs::create_directories(path, ec);
        return !ec;
    }

    // Odstránenie súboru
    [[nodiscard]] static bool remove_file(const fs::path& path) noexcept {
        std::error_code ec;
        return fs::remove(path, ec);
    }

    // Rekurzívne odstránenie priečinka
    [[nodiscard]] static std::uintmax_t remove_all(const fs::path& path) noexcept {
        std::error_code ec;
        return fs::remove_all(path, ec);
    }

    // Kopírovanie súboru
    [[nodiscard]] static bool copy_file(
        const fs::path& from,
        const fs::path& to,
        fs::copy_options options = fs::copy_options::none
    ) noexcept {
        std::error_code ec;
        fs::copy_file(from, to, options, ec);
        return !ec;
    }

    // Rekurzívne kopírovanie priečinka
    [[nodiscard]] static bool copy_recursive(
        const fs::path& from,
        const fs::path& to
    ) noexcept {
        std::error_code ec;
        fs::copy(from, to, fs::copy_options::recursive, ec);
        return !ec;
    }

    // Presun/premenovanie
    [[nodiscard]] static bool rename(const fs::path& from, const fs::path& to) noexcept {
        std::error_code ec;
        fs::rename(from, to, ec);
        return !ec;
    }

    // Získanie parent directory
    [[nodiscard]] static fs::path parent_path(const fs::path& path) {
        return path.parent_path();
    }

    // Získanie filename
    [[nodiscard]] static std::string filename(const fs::path& path) {
        return path.filename().string();
    }
};

} // namespace minidrive
