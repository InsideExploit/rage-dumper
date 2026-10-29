#pragma once

#include <windows.h>
#include <cstdint>

inline bool is_readable(uintptr_t addr, size_t size)
{
    if (addr < 0x10000 || addr > 0x7FFFFFFEFFFF || size == 0)
        return false;

    // most reads land in the same few heap regions, so remember the last good one
    static thread_local uintptr_t lo = 0;
    static thread_local uintptr_t hi = 0;

    if (addr >= lo && addr + size <= hi)
        return true;

    auto cur = addr;
    auto end = addr + size;

    while (cur < end)
    {
        MEMORY_BASIC_INFORMATION mbi{};

        if (!VirtualQuery(reinterpret_cast<void*>(cur), &mbi, sizeof(mbi)))
            return false;

        if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
            return false;

        const DWORD ok = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

        if (!(mbi.Protect & ok))
            return false;

        lo = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        hi = lo + mbi.RegionSize;
        cur = hi;
    }

    return true;
}

template <typename T>
inline bool read(uintptr_t addr, T& out)
{
    if (!is_readable(addr, sizeof(T)))
        return false;

    out = *reinterpret_cast<const T*>(addr);
    return true;
}
