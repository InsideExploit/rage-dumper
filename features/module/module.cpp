#include "module.hpp"
#include "../../utils/console.hpp"
#include "../../utils/memory.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

bool dump_module(HMODULE mod, const std::wstring& path)
{
    auto base = reinterpret_cast<uintptr_t>(mod);
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto size = nt->OptionalHeader.SizeOfImage;

    write_log(log_level::info, "dumping module image, 0x%X bytes...", size);

    std::vector<uint8_t> img(size, 0);
    uint32_t skipped = 0;

    for (uintptr_t cur = base; cur < base + size;)
    {
        MEMORY_BASIC_INFORMATION mbi{};

        if (!VirtualQuery(reinterpret_cast<void*>(cur), &mbi, sizeof(mbi)))
            break;

        auto lo = (std::max)(cur, reinterpret_cast<uintptr_t>(mbi.BaseAddress));
        auto hi = (std::min)(reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize, base + size);

        if (is_readable(lo, hi - lo))
            memcpy(img.data() + (lo - base), reinterpret_cast<const void*>(lo), hi - lo);
        else
            skipped += static_cast<uint32_t>(hi - lo);

        cur = hi;
    }

    // make the file layout match memory so IDA loads it as is
    auto out_nt = reinterpret_cast<IMAGE_NT_HEADERS*>(img.data() + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(out_nt);
    auto align = out_nt->OptionalHeader.SectionAlignment;

    out_nt->OptionalHeader.ImageBase = base;
    out_nt->OptionalHeader.FileAlignment = align;

    for (WORD i = 0; i < out_nt->FileHeader.NumberOfSections; i++, sec++)
    {
        auto vsize = (sec->Misc.VirtualSize + align - 1) & ~(align - 1);

        sec->PointerToRawData = sec->VirtualAddress;
        sec->SizeOfRawData = (std::min)(vsize, size - sec->VirtualAddress);
    }

    FILE* f = nullptr;

    if (_wfopen_s(&f, path.c_str(), L"wb") || !f)
    {
        write_log(log_level::error, "cannot write the module dump");
        return false;
    }

    fwrite(img.data(), 1, img.size(), f);
    fclose(f);

    write_log(log_level::ok, "module dumped, 0x%X bytes, %u bytes unreadable", size, skipped);
    return true;
}
