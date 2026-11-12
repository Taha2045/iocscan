// iocscan - hash-based IOC hunting.  Exit codes: 0 clean, 1 IOC match, 2 error.
#include <cstdlib>
#include <iostream>
#include <string>

#include "iocscan/scanner.hpp"

static void usage() {
    std::cerr << "usage: iocscan <path> -i <iocs.txt> [-t threads] [-m max_size_mb] [--json]\n"
                 "  <path>   file or directory to scan (symlinks are not followed)\n"
                 "  -i       IOC list: '<sha256> [description]' per line, '#' comments\n"
                 "  -t       worker threads (default: hardware concurrency)\n"
                 "  -m       skip files larger than N MB (default: 0 = no limit)\n"
                 "  --json   machine-readable output\n";
}

int main(int argc, char** argv) {
    std::string path, ioc_file;
    unsigned threads = 0;
    std::uintmax_t max_mb = 0;
    bool json = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* name) -> std::string {
            if (i + 1 >= argc) { std::cerr << "error: " << name << " needs a value\n"; usage(); std::exit(2); }
            return argv[++i];
        };
        try {
            if (a == "-i") ioc_file = need("-i");
            else if (a == "-t") threads = static_cast<unsigned>(std::stoul(need("-t")));
            else if (a == "-m") max_mb = std::stoull(need("-m"));
            else if (a == "--json") json = true;
            else if (a == "-h" || a == "--help") { usage(); return 0; }
            else if (!a.empty() && a[0] == '-') { std::cerr << "error: unknown option " << a << "\n"; usage(); return 2; }
            else path = a;
        } catch (const std::exception&) {
            std::cerr << "error: invalid numeric value for " << a << "\n";
            return 2;
        }
    }
    if (path.empty() || ioc_file.empty()) { usage(); return 2; }

    try {
        auto loaded = iocscan::load_iocs(ioc_file);
        for (const auto& w : loaded.warnings) std::cerr << "warning: " << w << "\n";
        if (loaded.iocs.empty()) { std::cerr << "error: no valid IOCs loaded\n"; return 2; }

        auto res = iocscan::scan(path, loaded.iocs, threads, max_mb * 1024 * 1024);

        if (json) {
            std::cout << iocscan::to_json(res);
        } else {
            for (const auto& m : res.matches)
                std::cout << "[MATCH] " << m.path.generic_string() << "\n        sha256=" << m.sha256
                          << "\n        ioc=" << m.description << "\n";
            for (const auto& e : res.errors) std::cerr << "error: " << e << "\n";
            std::cout << "\nScanned " << res.files_scanned << " file(s), " << res.files_skipped << " skipped, "
                      << res.matches.size() << " IOC match(es), " << loaded.iocs.size() << " IOC(s) loaded.\n";
        }
        return res.matches.empty() ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 2;
    }
}
