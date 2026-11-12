// Dependency-free test runner (no GoogleTest needed).
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#include "iocscan/scanner.hpp"
#include "iocscan/sha256.hpp"

namespace fs = std::filesystem;
using namespace iocscan;

static int failures = 0, total = 0;
#define CHECK(cond)                                                                   \
    do {                                                                              \
        ++total;                                                                      \
        if (!(cond)) { ++failures; std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << "  " #cond "\n"; } \
    } while (0)

static void write(const fs::path& p, const std::string& s) {
    fs::create_directories(p.parent_path());
    std::ofstream(p, std::ios::binary) << s;
}

static void test_sha256_vectors() {  // NIST FIPS 180-4 / well-known vectors
    CHECK(sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    CHECK(sha256_hex(std::string(1000000, 'a')) ==
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

static void test_sha256_padding_boundaries() {  // lengths around the 55/56/64-byte padding edge
    for (std::size_t n : {54, 55, 56, 57, 63, 64, 65, 119, 120, 128}) {
        std::string s(n, 'x');
        Sha256 chunked;  // feed byte-by-byte; must equal one-shot
        for (char c : s) chunked.update(reinterpret_cast<const std::uint8_t*>(&c), 1);
        CHECK(chunked.hexdigest() == sha256_hex(s));
    }
    // known: 55 x 'a' and 56 x 'a'
    CHECK(sha256_hex(std::string(55, 'a')) == "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
    CHECK(sha256_hex(std::string(56, 'a')) == "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
}

static void test_ioc_parsing() {
    std::istringstream in(
        "# comment\n\n"
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD  Test Trojan  \r\n"
        "not-a-hash something\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n");
    auto r = parse_iocs(in);
    CHECK(r.iocs.size() == 2);
    CHECK(r.iocs.at("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == "Test Trojan  " ||
          r.iocs.at("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == "Test Trojan");
    CHECK(r.iocs.at("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "unnamed IOC");
    CHECK(r.warnings.size() == 1);  // malformed line reported, not silently dropped
}

static void test_scan() {
    fs::path root = fs::temp_directory_path() / "iocscan_test_tree";
    fs::remove_all(root);
    write(root / "clean.txt", "hello");
    write(root / "sub" / "dropper.bin", "abc");           // sha256("abc") is an IOC below
    write(root / "sub" / "deep" / "copy.dat", "abc");     // same content, different name: still caught
    write(root / "sub" / "big.bin", std::string(5000, 'z'));

    IocMap iocs{{"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "test-malware"}};

    auto r = scan(root, iocs, 4, 0);
    CHECK(r.files_scanned == 4);
    CHECK(r.matches.size() == 2);
    CHECK(r.matches[0].description == "test-malware");

    auto roomy = scan(root, iocs, 1, 1024 * 1024);  // 1 MiB limit (API takes bytes): nothing skipped
    CHECK(roomy.matches.size() == 2 && roomy.files_skipped == 0);

    auto tight = scan(root, iocs, 1, 100);  // 100-byte limit: only the 5000-byte file is skipped
    CHECK(tight.files_skipped == 1 && tight.files_scanned == 3 && tight.matches.size() == 2);

    auto single = scan(root / "sub" / "dropper.bin", iocs, 1, 0);  // single-file mode
    CHECK(single.matches.size() == 1);

    auto st = scan(root, iocs, 1, 0), mt = scan(root, iocs, 8, 0);  // thread count must not change results
    CHECK(st.matches.size() == mt.matches.size() && st.files_scanned == mt.files_scanned);

    bool threw = false;
    try { scan(root / "does_not_exist", iocs, 1, 0); } catch (const std::exception&) { threw = true; }
    CHECK(threw);
    fs::remove_all(root);
}

static void test_json() {
    CHECK(json_escape("a\"b\\c\n") == "a\\\"b\\\\c\\n");
    ScanResult r;
    r.files_scanned = 3;
    r.matches.push_back({"dir/evil \"x\".exe", "00", "bad"});
    auto j = to_json(r);
    CHECK(j.find("\"files_scanned\": 3") != std::string::npos);
    CHECK(j.find("evil \\\"x\\\".exe") != std::string::npos);
}

int main() {
    test_sha256_vectors();
    test_sha256_padding_boundaries();
    test_ioc_parsing();
    test_scan();
    test_json();
    std::cout << (total - failures) << "/" << total << " checks passed\n";
    return failures == 0 ? 0 : 1;
}
