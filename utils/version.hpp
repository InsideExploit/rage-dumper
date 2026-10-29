#pragma once

#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>

struct game_version
{
    std::string product = "RAGE";
    std::string build = "unknown";
};

inline game_version get_game_version()
{
    game_version v;
    wchar_t path[MAX_PATH]{};
    DWORD unused = 0;

    GetModuleFileNameW(nullptr, path, MAX_PATH);

    auto size = GetFileVersionInfoSizeW(path, &unused);

    if (!size)
        return v;

    std::vector<uint8_t> buf(size);

    if (!GetFileVersionInfoW(path, 0, size, buf.data()))
        return v;

    VS_FIXEDFILEINFO* fixed = nullptr;
    UINT len = 0;

    if (VerQueryValueW(buf.data(), L"\\", reinterpret_cast<void**>(&fixed), &len) && fixed)
    {
        char s[64];
        sprintf_s(s, "%u.%u.%u.%u", HIWORD(fixed->dwFileVersionMS), LOWORD(fixed->dwFileVersionMS),
            HIWORD(fixed->dwFileVersionLS), LOWORD(fixed->dwFileVersionLS));

        v.build = s;
    }

    struct translation
    {
        WORD lang;
        WORD page;
    };

    translation* tr = nullptr;

    if (!VerQueryValueW(buf.data(), L"\\VarFileInfo\\Translation", reinterpret_cast<void**>(&tr), &len) || len < sizeof(translation))
        return v;

    wchar_t key[64];
    swprintf_s(key, L"\\StringFileInfo\\%04x%04x\\ProductName", tr->lang, tr->page);

    wchar_t* name = nullptr;

    if (VerQueryValueW(buf.data(), key, reinterpret_cast<void**>(&name), &len) && name && len)
    {
        char out[256]{};
        WideCharToMultiByte(CP_UTF8, 0, name, -1, out, sizeof(out) - 1, nullptr, nullptr);
        v.product = out;
    }

    return v;
}
