#include "iocscan/scanner.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>

#include "iocscan/sha256.hpp"

namespace fs = std::filesystem;

namespace iocscan {

static bool is_sha256_hex(const std::string& s) {
    return s.size() == 64 && std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c); });
}

IocLoadResult parse_iocs(std::istream& in) {
    IocLoadResult res;
    std::string line;
    std::size_t lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::size_t start = line.find_first_not_of(" \t");
        if (start == std::string::npos || line[start] == '#') continue;
        std::istringstream ss(line.substr(start));
        std::string hash;
        ss >> hash;
        if (!is_sha256_hex(hash)) {
            res.warnings.push_back("line " + std::to_string(lineno) + ": not a valid SHA-256, ignored");
            continue;
        }
        std::transform(hash.begin(), hash.end(), hash.begin(), [](unsigned char c) { return std::tolower(c); });
        std::string desc;
        std::getline(ss, desc);
        std::size_t d = desc.find_first_not_of(" \t");
        res.iocs[hash] = (d == std::string::npos) ? "unnamed IOC" : desc.substr(d);
    }
    return res;
}

IocLoadResult load_iocs(const fs::path& file) {
    std::ifstream in(file);
    if (!in) throw std::runtime_error("cannot open IOC file: " + file.string());
    return parse_iocs(in);
}

ScanResult scan(const fs::path& root, const IocMap& iocs, unsigned threads, std::uintmax_t max_size) {
    ScanResult result;
    std::vector<fs::path> files;

    std::error_code ec;
    if (fs::is_regular_file(root, ec)) {
        files.push_back(root);
    } else {
        fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
        if (ec) throw std::runtime_error("cannot read directory: " + root.string() + " (" + ec.message() + ")");
        for (; it != end; it.increment(ec)) {
            if (ec) { result.errors.push_back("walk error: " + ec.message()); ec.clear(); continue; }
            std::error_code e2;
            if (it->is_regular_file(e2) && !it->is_symlink(e2)) files.push_back(it->path());
        }
    }
    std::sort(files.begin(), files.end());

    if (threads == 0) threads = std::max(1u, std::thread::hardware_concurrency());
    threads = std::min<unsigned>(threads, static_cast<unsigned>(std::max<std::size_t>(files.size(), 1)));

    std::atomic<std::size_t> next{0}, scanned{0}, skipped{0};
    std::mutex mtx;  // guards result.matches / result.errors

    auto worker = [&] {
        for (std::size_t i = next++; i < files.size(); i = next++) {
            const fs::path& p = files[i];
            std::error_code e;
            auto size = fs::file_size(p, e);
            if (!e && max_size > 0 && size > max_size) { ++skipped; continue; }
            try {
                std::string digest = sha256_file(p);
                ++scanned;
                auto hit = iocs.find(digest);
                if (hit != iocs.end()) {
                    std::lock_guard<std::mutex> lock(mtx);
                    result.matches.push_back({p, digest, hit->second});
                }
            } catch (const std::exception& ex) {
                std::lock_guard<std::mutex> lock(mtx);
                result.errors.emplace_back(ex.what());
            }
        }
    };

    std::vector<std::thread> pool;
    for (unsigned t = 0; t < threads; ++t) pool.emplace_back(worker);
    for (auto& t : pool) t.join();

    result.files_scanned = scanned;
    result.files_skipped = skipped;
    std::sort(result.matches.begin(), result.matches.end(),
              [](const Match& a, const Match& b) { return a.path < b.path; });
    std::sort(result.errors.begin(), result.errors.end());
    return result;
}

std::string json_escape(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); out += b; }
                else out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

std::string to_json(const ScanResult& r) {
    std::ostringstream o;
    o << "{\n  \"files_scanned\": " << r.files_scanned << ",\n  \"files_skipped\": " << r.files_skipped
      << ",\n  \"matches\": [";
    for (std::size_t i = 0; i < r.matches.size(); ++i) {
        const auto& m = r.matches[i];
        o << (i ? "," : "") << "\n    {\"path\": \"" << json_escape(m.path.generic_string()) << "\", \"sha256\": \""
          << m.sha256 << "\", \"description\": \"" << json_escape(m.description) << "\"}";
    }
    o << (r.matches.empty() ? "" : "\n  ") << "],\n  \"errors\": [";
    for (std::size_t i = 0; i < r.errors.size(); ++i)
        o << (i ? ", " : "") << "\"" << json_escape(r.errors[i]) << "\"";
    o << "]\n}\n";
    return o.str();
}

}  // namespace iocscan
