#pragma once

#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace minidrive::client {

// Parsovaný príkaz
struct ParsedCommand {
    std::string name;
    std::vector<std::string> args;

    [[nodiscard]] bool has_arg(std::size_t index) const noexcept {
        return index < args.size();
    }

    [[nodiscard]] const std::string& arg(std::size_t index) const {
        return args.at(index);
    }

    [[nodiscard]] std::string arg_or(std::size_t index, const std::string& default_value) const {
        return index < args.size() ? args[index] : default_value;
    }
};

// Parser príkazov z command line
class CommandParser {
public:
    // Parsovanie príkazu
    [[nodiscard]] static std::optional<ParsedCommand> parse(const std::string& line) {
        if (line.empty()) {
            return std::nullopt;
        }

        ParsedCommand cmd;
        std::vector<std::string> tokens = tokenize(line);

        if (tokens.empty()) {
            return std::nullopt;
        }

        // Prvý token je názov príkazu (uppercase)
        cmd.name = to_upper(tokens[0]);

        // Ostatné tokeny sú argumenty
        for (std::size_t i = 1; i < tokens.size(); ++i) {
            cmd.args.push_back(tokens[i]);
        }

        return cmd;
    }

private:
    // Tokenizácia - podporuje úvodzovky
    [[nodiscard]] static std::vector<std::string> tokenize(const std::string& line) {
        std::vector<std::string> tokens;
        std::string current;
        bool in_quotes = false;
        char quote_char = '\0';

        for (std::size_t i = 0; i < line.size(); ++i) {
            char c = line[i];

            if (in_quotes) {
                if (c == quote_char) {
                    in_quotes = false;
                    // Pridáme token aj keď je prázdny (prázdne úvodzovky)
                    tokens.push_back(current);
                    current.clear();
                } else if (c == '\\' && i + 1 < line.size()) {
                    // Escape sequence
                    char next = line[i + 1];
                    if (next == quote_char || next == '\\') {
                        current += next;
                        ++i;
                    } else {
                        current += c;
                    }
                } else {
                    current += c;
                }
            } else {
                if (c == '"' || c == '\'') {
                    in_quotes = true;
                    quote_char = c;
                    // Ak máme rozpracovaný token, dokončíme ho
                    if (!current.empty()) {
                        tokens.push_back(current);
                        current.clear();
                    }
                } else if (std::isspace(static_cast<unsigned char>(c))) {
                    if (!current.empty()) {
                        tokens.push_back(current);
                        current.clear();
                    }
                } else {
                    current += c;
                }
            }
        }

        // Posledný token
        if (!current.empty()) {
            tokens.push_back(current);
        }

        return tokens;
    }

    // Konverzia na uppercase
    [[nodiscard]] static std::string to_upper(std::string str) {
        for (char& c : str) {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        return str;
    }
};

// Help text pre príkazy
inline const char* HELP_TEXT = R"(
Available commands:

Local Commands:
  HELP                          Show this help message
  EXIT                          Close connection and exit

File Commands:
  LIST [path]                   List files in directory
  UPLOAD <local> [remote]       Upload file to server
  DOWNLOAD <remote> [local]     Download file from server
  DELETE <path>                 Delete file on server

Directory Commands:
  CD <path>                     Change current directory
  MKDIR <path>                  Create directory
  RMDIR <path>                  Remove directory (recursive)
  MOVE <src> <dst>              Move/rename file or directory
  COPY <src> <dst>              Copy file or directory

Synchronization:
  SYNC <local> <remote>         Sync local directory to server

Notes:
  - Paths starting with / are absolute (relative to user root)
  - Other paths are relative to current directory
  - Use quotes for paths with spaces: "my file.txt"
)";

} // namespace minidrive::client
