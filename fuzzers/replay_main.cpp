// replay_main.cpp — runs every file under the given directories (or the given
// files) through LLVMFuzzerTestOneInput once. Linked with each harness in the
// normal build so seed + regression corpora are a plain ctest.

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

namespace {

constexpr std::size_t kMaxInputBytes = 4u << 20;
constexpr std::size_t kMaxFiles = 100000;

bool run_file(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "replay: cannot open %s\n", p.string().c_str());
        return false;
    }
    std::vector<char> buf((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());
    if (buf.size() > kMaxInputBytes) {
        std::fprintf(stderr, "replay: %s exceeds %zu bytes\n", p.string().c_str(),
                     kMaxInputBytes);
        return false;
    }
    // Exact-size heap copy so an over-read past the input is visible to ASan.
    std::vector<std::uint8_t> exact(buf.begin(), buf.end());
    LLVMFuzzerTestOneInput(exact.empty() ? nullptr : exact.data(), exact.size());
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    assert(argc >= 1);
    std::size_t ran = 0;
    for (int i = 1; i < argc; ++i) {
        const std::filesystem::path root(argv[i]);
        std::error_code ec;
        if (std::filesystem::is_regular_file(root, ec)) {
            if (!run_file(root)) return 1;
            ++ran;
            continue;
        }
        if (!std::filesystem::is_directory(root, ec)) continue;  // no crashes yet
        std::vector<std::filesystem::path> files;
        for (const auto& e : std::filesystem::directory_iterator(root, ec)) {
            if (files.size() >= kMaxFiles) break;
            if (e.is_regular_file()) files.push_back(e.path());
        }
        for (const auto& f : files) {
            std::fprintf(stderr, "replay: %s\n", f.filename().string().c_str());
            if (!run_file(f)) return 1;
            ++ran;
        }
    }
    std::fprintf(stderr, "replay: %zu inputs OK\n", ran);
    assert(ran <= kMaxFiles * static_cast<std::size_t>(argc));
    return ran == 0 ? 1 : 0;
}
