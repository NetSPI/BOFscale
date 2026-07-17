
#ifndef STDLIB_H
#define STDLIB_H

#include <fstream>
#include <vector>
#include <functional>

static constexpr uint32_t djb2a(const char* s, const uint32_t h = 5381) {
    return !*s ? h : djb2a(s + 1, 33 * h ^ (uint8_t)*s);
}

static constexpr uint32_t djb2a(const wchar_t* s, const uint32_t h = 5381) {
    return !*s ? h : djb2a(s + 1, 33 * h ^ (uint8_t)*s);
}

static constexpr uint32_t djb2a(const char* s, int len, const uint32_t h = 5381) {
    return !len ? h : djb2a(s + 1, len - 1, 33 * h ^ (uint8_t)*s);
}

//https://stackoverflow.com/questions/51352863/what-is-the-idiomatic-c17-standard-approach-to-reading-binary-files
template <typename T>
std::vector<T> LoadFile(std::string const& filepath)
{
    std::ifstream ifs(filepath, std::ios::binary|std::ios::ate);

    if(!ifs)
        throw std::runtime_error(filepath + ": " + std::strerror(errno));

    auto end = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    auto size = std::size_t(end - ifs.tellg());

    if(size == 0) // avoid undefined behavior
        return {};

    std::vector<std::byte> buffer(size);

    if(!ifs.read((char*)buffer.data(), buffer.size()))
        throw std::runtime_error(filepath + ": " + std::strerror(errno));

    return buffer;
}

class scoped_exit {
    std::function<void()> func_;
    bool active_ = true;
public:
    explicit scoped_exit(std::function<void()> f) : func_(std::move(f)) {}
    ~scoped_exit() { if (active_) func_(); }
    void dismiss() noexcept { active_ = false; }
};

#endif // STDLIB_H
