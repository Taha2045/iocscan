#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

namespace iocscan {

using IocMap = std::unordered_map<std::string, std::string>;  // sha256 -> description

struct IocLoadResult {
    IocMap iocs;
    std::vector<std::string> warnings;  // malformed lines (never silently dropped)
};

struct Match {
    std::filesystem::path path;
    std::string sha256;
    std::string description;
};

struct ScanResult {
    std::vector<Match> matches;
    std::size_t files_scanned = 0;
    std::size_t files_skipped = 0;  // larger than max_size
    std::vector<std::string> errors;
};

// Format: one IOC per line, "<sha256-hex> [description]". '#' starts a comment.
IocLoadResult load_iocs(const std::filesystem::path& file);
IocLoadResult parse_iocs(std::istream& in);

// Recursively scans regular files (symlinks are NOT followed). threads==0 -> hardware concurrency.
ScanResult scan(const std::filesystem::path& root, const IocMap& iocs, unsigned threads,
                std::uintmax_t max_size_bytes);

std::string to_json(const ScanResult& r);
std::string json_escape(const std::string& s);

}  // namespace iocscan
