#include <windows.h>
#include <string>

#include "features/module/module.hpp"
#include "features/natives/natives.hpp"
#include "features/parser/parser.hpp"
#include "features/writer/writer.hpp"
#include "utils/console.hpp"
#include "utils/version.hpp"

static DWORD WINAPI run(LPVOID param)
{
    auto self = static_cast<HMODULE>(param);
    wchar_t path[MAX_PATH]{};
    std::wstring dir;

    if (GetModuleFileNameW(self, path, MAX_PATH))
    {
        dir = path;
        dir.resize(dir.find_last_of(L"\\/") + 1);
    }
    else
    {
        // manual mapped, no module path to work with
        GetTempPathW(MAX_PATH, path);
        dir = std::wstring(path) + L"rage-dumper\\";
        CreateDirectoryW(dir.c_str(), nullptr);
    }

    open_console(dir + L"dump.log");
    write_log(log_level::ok, "rage-dumper loaded");
    write_log(log_level::info, "output folder: %ls", dir.c_str());

    auto game = GetModuleHandleW(nullptr);
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<uintptr_t>(game) + reinterpret_cast<const IMAGE_DOS_HEADER*>(game)->e_lfanew);

    auto version = get_game_version();

    write_log(log_level::info, "%s %s", version.product.c_str(), version.build.c_str());
    write_log(log_level::info, "game base 0x%llX, size 0x%X", reinterpret_cast<uintptr_t>(game), nt->OptionalHeader.SizeOfImage);

    auto out = dir + std::wstring(version.build.begin(), version.build.end()) + L"\\";
    CreateDirectoryW(out.c_str(), nullptr);

    dump_module(game, out + L"game_dump.exe");

    sdk_model model;
    bool ok = collect_parser(game, dir, model) && write_sdk(model, out);

    std::vector<native_info> natives;
    bool found = collect_natives(game, natives);

    if (found)
    {
        name_natives(natives, dir + L"natives.txt");
        pick_commands(natives);
    }

    ok = found && write_natives(natives, out) && ok;

    if (ok)
        write_log(log_level::ok, "all done");
    else
        write_log(log_level::error, "dump failed, check the lines above");

    close_log();

    // unload so the dll can be rebuilt and injected again without restarting the game
    if (GetModuleFileNameW(self, path, MAX_PATH))
        FreeLibraryAndExitThread(self, 0);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE mod, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(mod);

        if (auto t = CreateThread(nullptr, 0, run, mod, 0, nullptr))
            CloseHandle(t);
    }

    return TRUE;
}
