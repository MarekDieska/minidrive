# MiniDrive

## Project Description

MiniDrive is a client-server file synchronization system written in C++. The application enables file transfer and synchronization between a local machine and a remote server, similar to cloud storage services like OneDrive or Dropbox.

The system consists of two components:
- **Server** (`./build/server`) - Listens for client connections and manages the file repository
- **Client** (`./build/client`) - Connects to the server and provides an interactive command-line interface for file operations

### Key Features

- **File Operations**: Upload, download, delete, list files
- **Directory Operations**: Create, remove, move, copy directories
- **Synchronization**: One-way sync from local to remote with hash-based change detection
- **Authentication**: Public mode (shared storage) and private mode (per-user isolated storage)
- **Concurrent Access**: Multiple clients can connect simultaneously
- **Resume Transfers**: Interrupted uploads can be resumed after reconnection
- **Security**: Password hashing with Argon2id, path traversal prevention

### Technologies

- C++20
- BSD TCP Sockets
- nlohmann/json (serialization)
- libsodium (cryptography)
- spdlog (logging)
- CMake (build system)

