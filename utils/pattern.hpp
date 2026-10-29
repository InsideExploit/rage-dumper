#pragma once

#include <windows.h>
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <vector>

#include "memory.hpp"

inline uintptr_t find_pattern(uintptr_t base, const char* pattern)
{
    std::vector<int> bytes;

    for (auto p = pattern; *p;)
    {
        if (*p == ' ')
        {
            p++;
            continue;
        }

        if (*p == '?')
        {
            bytes.push_back(-1);

            while (*p == '?')
                p++;

            continue;
        }

        bytes.push_back(static_cast<int>(strtoul(p, const_cast<char**>(&p), 16)));
    }

    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        auto lo = base + sec->VirtualAddress;
        auto hi = lo + sec->Misc.VirtualSize;

        // scan region by region so a guarded or decommitted page never gets touched
        for (auto cur = lo; cur < hi;)
        {
            MEMORY_BASIC_INFORMATION mbi{};

            if (!VirtualQuery(reinterpret_cast<void*>(cur), &mbi, sizeof(mbi)))
                break;

            auto end = (std::min)(reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize, hi);
            auto size = static_cast<size_t>(end - cur);
            auto start = reinterpret_cast<const uint8_t*>(cur);

            if (is_readable(cur, size) && size >= bytes.size())
            {
                for (size_t j = 0; j <= size - bytes.size(); j++)
                {
                    bool hit = true;

                    for (size_t k = 0; k < bytes.size(); k++)
                    {
                        if (bytes[k] != -1 && start[j + k] != bytes[k])
                        {
                            hit = false;
                            break;
                        }
                    }

                    if (hit)
                        return cur + j;
                }
            }

            cur = end;
        }
    }

    return 0;
}

inline uintptr_t rip_resolve(uintptr_t addr, uint32_t disp_off, uint32_t insn_size)
{
    return addr + insn_size + *reinterpret_cast<const int32_t*>(addr + disp_off);
}
