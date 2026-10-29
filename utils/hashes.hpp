#pragma once

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <unordered_map>

using hash_map = std::unordered_map<uint32_t, std::string>;

inline hash_map load_hashes(const std::wstring& path)
{
    hash_map out;
    FILE* f = nullptr;

    if (_wfopen_s(&f, path.c_str(), L"rb") || !f)
        return out;

    char line[512];

    while (fgets(line, sizeof(line), f))
    {
        char* end = nullptr;
        auto h = static_cast<uint32_t>(strtoul(line, &end, 16));

        if (end == line || *end != ' ')
            continue;

        std::string s = end + 1;

        while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
            s.pop_back();

        out.emplace(h, std::move(s));
    }

    fclose(f);
    return out;
}

inline std::string hash_name(const hash_map& map, uint32_t h)
{
    auto it = map.find(h);

    if (it != map.end())
        return it->second;

    char buf[16];
    sprintf_s(buf, "_0x%08X", h);
    return buf;
}
