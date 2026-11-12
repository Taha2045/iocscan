#pragma once
// Self-contained SHA-256 (FIPS 180-4). Streaming API, no dependencies.
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace iocscan {

class Sha256 {
public:
    Sha256();
    void update(const std::uint8_t* data, std::size_t len);
    std::string hexdigest();  // finalizes; the object must not be updated afterwards

private:
    void transform(const std::uint8_t* block);
    std::uint32_t state_[8];
    std::uint8_t buffer_[64];
    std::size_t buflen_;
    std::uint64_t total_bytes_;
    bool finalized_;
};

std::string sha256_hex(std::string_view data);
// Streams the file in 64 KiB chunks (constant memory). Throws std::runtime_error on I/O failure.
std::string sha256_file(const std::filesystem::path& path);

}  // namespace iocscan
