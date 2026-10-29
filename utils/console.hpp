#pragma once

#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <string>

enum class log_level
{
    info,
    ok,
    warn,
    error,
};

// shared between every feature that logs, mirrors the console into dump.log
inline FILE* log_file = nullptr;

inline void open_console(const std::wstring& log_path)
{
    if (AllocConsole())
    {
        FILE* f = nullptr;
        freopen_s(&f, "CONOUT$", "w", stdout);

        SetConsoleTitleW(L"RAGE dumper");

        auto out = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;

        if (GetConsoleMode(out, &mode))
            SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

        // closing a console kills its owning process, so keep the game alive
        if (auto menu = GetSystemMenu(GetConsoleWindow(), FALSE))
            DeleteMenu(menu, SC_CLOSE, MF_BYCOMMAND);
    }

    _wfopen_s(&log_file, log_path.c_str(), L"w");
}

inline void write_log(log_level lvl, const char* fmt, ...)
{
    static const char* tags[] = { "[*]", "[+]", "[!]", "[-]" };
    static const char* colors[] = { "\x1b[96m", "\x1b[92m", "\x1b[93m", "\x1b[91m" };

    char msg[1024];
    va_list args;

    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    SYSTEMTIME t{};
    GetLocalTime(&t);

    auto i = static_cast<int>(lvl);

    printf("\x1b[90m%02d:%02d:%02d %s%s\x1b[0m %s\n", t.wHour, t.wMinute, t.wSecond, colors[i], tags[i], msg);
    fflush(stdout);

    if (log_file)
    {
        fprintf(log_file, "%02d:%02d:%02d %s %s\n", t.wHour, t.wMinute, t.wSecond, tags[i], msg);
        fflush(log_file);
    }
}

inline void close_log()
{
    if (log_file)
        fclose(log_file);

    log_file = nullptr;
}
