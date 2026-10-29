#include "parser.hpp"
#include "../../utils/console.hpp"
#include "../../utils/hashes.hpp"
#include "../../utils/memory.hpp"
#include "../../utils/pattern.hpp"

#include <algorithm>
#include <set>
#include <unordered_map>
#include <unordered_set>

struct map_entry
{
    uint32_t key;
    uintptr_t data;
    uintptr_t next;
};

struct at_map
{
    uintptr_t hash;
    uint16_t slots;
    uint16_t used;
};

struct par_structure
{
    uintptr_t vtable;
    uint32_t name_hash;
    uintptr_t base;
    uint64_t base_offset;
    uint64_t size;
    uint8_t flags;
    uint8_t reg_count;
    uint16_t align;
    uint32_t version;
    uintptr_t members;
    uint16_t member_count;
    uint16_t member_capacity;
};

struct par_member_data
{
    uint32_t name_hash;
    uint64_t offset;
    uint8_t type;
    uint8_t subtype;
    uint16_t flags;
    uint16_t visit_flags;
    uint16_t type_flags;
    uintptr_t attributes;
};

struct par_enum_entry
{
    uint32_t name_hash;
    int32_t value;
};

struct par_enum_data
{
    uintptr_t entries;
    uintptr_t names;
    uint16_t count;
    uint16_t flags;
    uint32_t name_hash;
};

struct enum_use
{
    par_enum_data data;
    std::set<uint32_t> sizes;
    bool bits = false;
};

struct dump_ctx
{
    uintptr_t image_lo;
    uintptr_t image_hi;
    hash_map hashes;
    std::unordered_map<uintptr_t, par_structure> structs;
    std::unordered_map<uintptr_t, enum_use> enums;
    std::unordered_set<uint32_t> missing;
};

static std::string name_of(dump_ctx& c, uint32_t h)
{
    if (!c.hashes.count(h))
        c.missing.insert(h);

    return hash_name(c.hashes, h);
}

template <typename F>
static void scan_data(const dump_ctx& c, F fn)
{
    auto base = c.image_lo;
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        auto ch = sec->Characteristics;

        if (!(ch & IMAGE_SCN_MEM_WRITE) || (ch & IMAGE_SCN_MEM_EXECUTE))
            continue;

        auto lo = base + sec->VirtualAddress;
        auto hi = lo + sec->Misc.VirtualSize;

        for (auto page = lo; page < hi; page += 0x1000)
        {
            auto page_end = (std::min)(page + 0x1000, hi);

            if (!is_readable(page, page_end - page))
                continue;

            for (auto p = page; p + 8 <= page_end; p += 8)
            {
                if (!fn(p, *reinterpret_cast<const uintptr_t*>(p)))
                    return;
            }
        }
    }
}

template <typename F>
static void walk_map(uintptr_t addr, F fn)
{
    at_map map{};

    if (!read(addr, map) || !is_readable(map.hash, map.slots * 8ull))
        return;

    // bounded so a corrupted chain can never spin forever
    uint32_t budget = map.used * 2u + 16u;

    for (uint32_t i = 0; i < map.slots; i++)
    {
        auto e = reinterpret_cast<const uintptr_t*>(map.hash)[i];

        while (e && budget)
        {
            map_entry entry{};

            if (!read(e, entry))
                break;

            if (!fn(entry))
                return;

            e = entry.next;
            budget--;
        }
    }
}

static bool check_map(const dump_ctx& c, uintptr_t addr, uint32_t key_off, uint16_t min_used, bool has_vtable)
{
    at_map map{};

    if (!read(addr, map) || map.slots < 16 || map.used < min_used || map.used > map.slots * 16u)
        return false;

    int checked = 0;
    bool ok = true;

    walk_map(addr, [&](const map_entry& entry)
    {
        uint32_t key = 0;

        if (!read(entry.data + key_off, key) || key != entry.key)
        {
            ok = false;
            return false;
        }

        uintptr_t vt = 0;

        if (has_vtable && (!read(entry.data, vt) || vt < c.image_lo || vt >= c.image_hi))
        {
            ok = false;
            return false;
        }

        return ++checked < 16;
    });

    return ok && checked > 0 && checked >= (std::min)(8, static_cast<int>(map.used));
}

static void describe_map(const dump_ctx& c, uintptr_t addr)
{
    at_map map{};

    if (!read(addr, map))
    {
        write_log(log_level::error, "map at 0x%llX is not readable", addr);
        return;
    }

    write_log(log_level::info, "map at 0x%llX: buckets 0x%llX, slots %u, used %u", addr, map.hash, map.slots, map.used);

    int shown = 0;

    walk_map(addr, [&](const map_entry& entry)
    {
        uintptr_t vt = 0;
        uint32_t h8 = 0;
        uint32_t h14 = 0;

        read(entry.data, vt);
        read(entry.data + 0x08, h8);
        read(entry.data + 0x14, h14);

        write_log(log_level::info, "  key 0x%08X data 0x%llX vt image+0x%llX +8 0x%08X +14 0x%08X",
            entry.key, entry.data, vt - c.image_lo, h8, h14);

        return ++shown < 4;
    });
}

static bool find_manager(const dump_ctx& c, uintptr_t& mgr, uint32_t& off)
{
    // start of parStructure::BuildStructureFromStaticData, same bytes in retail 1.0.3889 and the bank build
    auto hit = find_pattern(c.image_lo, "48 8B 05 ?? ?? ?? ?? 48 83 7A 28 00 48 8B FA 44 8A 60 5C");

    if (hit)
    {
        auto global = rip_resolve(hit, 3, 7);

        write_log(log_level::ok, "pattern hit at image+0x%llX", hit - c.image_lo);
        write_log(log_level::ok, "parManager::sm_Instance at image+0x%llX", global - c.image_lo);

        if (read(global, mgr) && mgr)
        {
            off = 0x30;

            if (check_map(c, mgr + off, 0x08, 1, true))
                return true;

            write_log(log_level::warn, "m_Structures at +0x30 did not validate:");
            describe_map(c, mgr + off);
        }
        else
        {
            write_log(log_level::warn, "sm_Instance is null, the parser is not initialized yet");
        }
    }
    else
    {
        write_log(log_level::warn, "pattern not found, falling back to the .data scan (slow)");
    }

    bool found = false;

    scan_data(c, [&](uintptr_t p, uintptr_t q)
    {
        if (q < 0x10000 || (q & 7) || !is_readable(q, 0x60))
            return true;

        for (uint32_t o : { 0x30u, 0x20u, 0x40u, 0x10u, 0x00u, 0x50u })
        {
            if (check_map(c, q + o, 0x08, 100, true))
            {
                write_log(log_level::ok, "scan hit, global at image+0x%llX", p - c.image_lo);

                mgr = q;
                off = o;
                found = true;
                return false;
            }
        }

        return true;
    });

    return found;
}

static uintptr_t struct_ptr(const dump_ctx& c, uintptr_t data)
{
    // m_StructurePtr moves when bank-only fields are compiled out, so match it by value
    for (uint32_t o = 0x20; o <= 0x30; o += 8)
    {
        uintptr_t q = 0;

        if (read(data + o, q) && c.structs.count(q))
            return q;
    }

    return 0;
}

// retail never fills m_Enums, but every enum and bitset member keeps its parEnumData at +0x28
static void collect_enums(dump_ctx& c, uintptr_t obj, int depth = 0)
{
    uintptr_t data = 0;
    par_member_data d{};

    if (depth > 8 || !read(obj + 8, data) || !read(data, d))
        return;

    if (d.type == type_enum || d.type == type_bitset)
    {
        uintptr_t p = 0;
        par_enum_data e{};

        if (read(data + 0x28, p) && read(p, e) && e.count && e.count <= 4096 &&
            is_readable(e.entries, e.count * sizeof(par_enum_entry)))
        {
            auto& use = c.enums[p];
            use.data = e;

            if (d.type == type_bitset)
                use.bits = true;
            else
                use.sizes.insert(d.subtype == 2 ? 1 : d.subtype == 1 ? 2 : 4);
        }
    }
    else if (d.type == type_array)
    {
        uintptr_t proto = 0;

        if (read(obj + 0x10, proto) && proto)
            collect_enums(c, proto, depth + 1);
    }
    else if (d.type == type_map)
    {
        uintptr_t key = 0;
        uintptr_t val = 0;

        if (read(obj + 0x10, key) && key)
            collect_enums(c, key, depth + 1);

        if (read(obj + 0x18, val) && val)
            collect_enums(c, val, depth + 1);
    }
}

static std::string enum_name(dump_ctx& c, uintptr_t data)
{
    uintptr_t p = 0;

    if (read(data + 0x28, p) && c.enums.count(p))
        return name_of(c, c.enums.at(p).data.name_hash);

    return "";
}

static member_desc describe(dump_ctx& c, uintptr_t obj, int depth = 0)
{
    member_desc m;
    uintptr_t data = 0;
    par_member_data d{};

    if (depth > 8 || !read(obj + 8, data) || !read(data, d))
        return m;

    m.type = d.type;
    m.subtype = d.subtype;

    switch (d.type)
    {
    case type_string:
        read(data + 0x20, m.count);
        break;

    case type_struct:
        if (auto s = struct_ptr(c, data))
            m.ref = name_of(c, c.structs.at(s).name_hash);

        break;

    case type_array:
    {
        uintptr_t proto = 0;
        read(data + 0x28, m.count);

        if (read(obj + 0x10, proto) && proto)
            m.sub.push_back(describe(c, proto, depth + 1));

        break;
    }

    case type_enum:
        m.ref = enum_name(c, data);
        break;

    case type_bitset:
    {
        uint16_t bits = 0;
        read(data + 0x30, bits);

        m.count = bits;
        m.ref = enum_name(c, data);
        break;
    }

    case type_map:
    {
        uintptr_t key = 0;
        uintptr_t val = 0;

        read(obj + 0x10, key);
        read(obj + 0x18, val);

        m.sub.push_back(key ? describe(c, key, depth + 1) : member_desc{});
        m.sub.push_back(val ? describe(c, val, depth + 1) : member_desc{});
        break;
    }
    }

    return m;
}

bool collect_parser(HMODULE game, const std::wstring& dir, sdk_model& out)
{
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<uintptr_t>(game) + reinterpret_cast<const IMAGE_DOS_HEADER*>(game)->e_lfanew);

    dump_ctx c{};
    c.image_lo = reinterpret_cast<uintptr_t>(game);
    c.image_hi = c.image_lo + nt->OptionalHeader.SizeOfImage;

    write_log(log_level::info, "loading hashes.txt...");
    c.hashes = load_hashes(dir + L"hashes.txt");

    if (c.hashes.empty())
        write_log(log_level::warn, "no hashes loaded, every name will show as _0xHASH");
    else
        write_log(log_level::ok, "hashes loaded: %zu", c.hashes.size());

    write_log(log_level::info, "looking for parManager...");

    uintptr_t mgr = 0;
    uint32_t off = 0;

    if (!find_manager(c, mgr, off))
    {
        write_log(log_level::error, "parManager not found, inject after the game finished loading");
        return false;
    }

    write_log(log_level::ok, "parManager instance 0x%llX", mgr);
    write_log(log_level::info, "m_Structures at +0x%X, m_Enums at +0x%X", off, off + 0x10);

    // more than one global can hold the instance, list them all so the right one gets a pattern
    scan_data(c, [&](uintptr_t p, uintptr_t q)
    {
        if (q == mgr)
            write_log(log_level::ok, "global holding it: image+0x%llX", p - c.image_lo);

        return true;
    });

    walk_map(mgr + off, [&](const map_entry& entry)
    {
        par_structure s{};

        if (read(entry.data, s))
            c.structs.emplace(entry.data, s);

        return true;
    });

    walk_map(mgr + off + 0x10, [&](const map_entry& entry)
    {
        par_enum_data e{};

        if (read(entry.data, e))
            c.enums[entry.data].data = e;

        return true;
    });

    write_log(log_level::ok, "structures: %zu", c.structs.size());
    write_log(log_level::info, "enums in m_Enums: %zu", c.enums.size());

    for (auto& [ptr, s] : c.structs)
    {
        if (!is_readable(s.members, s.member_count * 8ull))
            continue;

        for (uint16_t i = 0; i < s.member_count; i++)
            collect_enums(c, reinterpret_cast<const uintptr_t*>(s.members)[i]);
    }

    write_log(log_level::ok, "enums after walking members: %zu", c.enums.size());

    for (auto& [ptr, s] : c.structs)
    {
        struct_info info;
        info.name = name_of(c, s.name_hash);
        info.hash = s.name_hash;
        info.size = s.size;
        info.base_offset = s.base_offset;

        if (s.base && c.structs.count(s.base))
            info.base = name_of(c, c.structs.at(s.base).name_hash);

        if (is_readable(s.members, s.member_count * 8ull))
        {
            for (uint16_t i = 0; i < s.member_count; i++)
            {
                auto obj = reinterpret_cast<const uintptr_t*>(s.members)[i];
                uintptr_t data = 0;
                par_member_data d{};

                if (!read(obj + 8, data) || !read(data, d))
                    continue;

                info.fields.push_back({ name_of(c, d.name_hash), d.offset, describe(c, obj) });
            }
        }

        std::stable_sort(info.fields.begin(), info.fields.end(), [](auto& a, auto& b) { return a.offset < b.offset; });
        out.structs.push_back(std::move(info));
    }

    for (auto& [ptr, use] : c.enums)
    {
        enum_info info;
        info.name = name_of(c, use.data.name_hash);
        info.hash = use.data.name_hash;
        info.bits = use.bits;
        info.size = use.sizes.size() == 1 ? *use.sizes.begin() : 4;

        if (is_readable(use.data.entries, use.data.count * sizeof(par_enum_entry)))
        {
            auto e = reinterpret_cast<const par_enum_entry*>(use.data.entries);

            for (uint16_t i = 0; i < use.data.count; i++)
                info.values.emplace_back(name_of(c, e[i].name_hash), e[i].value);
        }

        std::stable_sort(info.values.begin(), info.values.end(), [](auto& a, auto& b) { return a.second < b.second; });
        out.enums.push_back(std::move(info));
    }

    std::sort(out.structs.begin(), out.structs.end(), [](auto& a, auto& b) { return a.name < b.name; });
    std::sort(out.enums.begin(), out.enums.end(), [](auto& a, auto& b) { return a.name < b.name; });

    out.missing.assign(c.missing.begin(), c.missing.end());
    std::sort(out.missing.begin(), out.missing.end());

    if (out.missing.empty())
        write_log(log_level::ok, "every hash resolved");
    else
        write_log(log_level::warn, "unresolved hashes: %zu", out.missing.size());

    return true;
}
