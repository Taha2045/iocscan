# 🧲 IOCScan

![CI](https://github.com/Taha2045/iocscan/actions/workflows/ci.yml/badge.svg)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A fast, dependency-free **IOC hunting** tool in modern C++: it walks a directory tree, hashes every file with
**SHA-256** and reports files whose hash appears in a list of known-bad indicators (threat-intel feeds,
incident-response notes, MalwareBazaar exports...). The same technique EDR products use for
"known-bad file" detection, in ~400 lines you can read in one sitting.

```
$ ./build/iocscan /srv/uploads -i iocs.txt
[MATCH] /srv/uploads/downloads/invoice_update.exe
        sha256=3f7b4809...665e81
        ioc=Simulated dropper (demo payload)
[MATCH] /srv/uploads/downloads/tmp/svchost_copy.exe      <- renamed copy: still caught (hash, not filename)
        ...
Scanned 3 file(s), 0 skipped, 2 IOC match(es), 1 IOC(s) loaded.
```

## Build & run

Requires a C++17 compiler (g++ or clang++) and `make`.

```bash
make                       # -> build/iocscan
make test                  # unit tests
make sanitize              # same tests under AddressSanitizer + UBSan
make tsan                  # same tests under ThreadSanitizer (worker pool race check)

sh samples/make_demo.sh /tmp/demo          # harmless demo tree with a simulated "malware" file
./build/iocscan /tmp/demo -i samples/iocs.txt
./build/iocscan /home -i iocs.txt -t 8 -m 200 --json     # 8 threads, skip files > 200 MB, JSON output
```

| Option | Meaning |
|---|---|
| `-i FILE` | IOC list: `<sha256> [description]` per line, `#` comments, case-insensitive hex |
| `-t N` | Worker threads (default: hardware concurrency) |
| `-m MB` | Skip files larger than N MB |
| `--json` | Machine-readable output for SIEM / SOAR ingestion |

**Exit codes:** `0` clean | `1` IOC match found | `2` error - so it drops straight into cron jobs and pipelines.

## Engineering notes

- **SHA-256 implemented from scratch** (FIPS 180-4) and verified against NIST vectors, the 1,000,000 x `a` vector,
  every padding boundary (54-128 bytes, byte-by-byte vs one-shot), and cross-checked against `sha256sum` on a 50 MB file.
- **Streaming I/O:** files are hashed in 64 KiB chunks, so memory use is constant regardless of file size.
- **Parallel scan:** lock-free work distribution (`std::atomic` index) over a sorted file list; a mutex guards only the
  result vector. Output is sorted, so results are **deterministic** whatever the thread count (tested).
- **Safe by default:** symlinks are not followed; unreadable files are reported, not fatal; malformed IOC lines produce a
  warning instead of being silently dropped; an IOC list with no valid entries is an error (a scan that can never match
  must not report "clean").
- CI builds with **g++ and clang++** and runs the suite under ASan, UBSan and TSan.

## Limitations (important)

- **Exact-hash matching is easy to evade:** changing one byte of a sample changes its hash. IOC hashes are short-lived;
  treat this as one layer next to behavioural detection and YARA rules, not a replacement for an EDR.
- The hand-written SHA-256 is for learning and portability. For production, link OpenSSL/libsodium (hardware-accelerated).
- Not tested on Windows/macOS (uses only standard C++17, so it should port; PRs welcome).
- No archive unpacking; files are scanned as-is.

## Roadmap

- [ ] MD5/SHA-1 IOC support (many feeds still publish them)   - [ ] Basic YARA-style byte-pattern rules
- [ ] `--watch` mode (inotify)   - [ ] CMake build for MSVC

## License

MIT
