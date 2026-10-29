#include "natives.hpp"
#include "../../utils/console.hpp"
#include "../../utils/insn.hpp"
#include "../../utils/memory.hpp"
#include "../../utils/pattern.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <unordered_map>

struct xor_field
{
    uint32_t lo;
    uint32_t hi;
    uint32_t key;
};

struct entry_count
{
    uint32_t a;
    uint32_t b;
};

// every encoded qword is followed by its key, and the key is mixed with the low half of the field's own address
static bool decode(uintptr_t addr, uint64_t& out)
{
    xor_field f{};

    if (!read(addr, f))
        return false;

    auto k = f.key ^ static_cast<uint32_t>(addr);
    out = (static_cast<uint64_t>(f.hi ^ k) << 32) | (f.lo ^ k);
    return true;
}

// lea rsp, [rsp+8]; jmp [rsp-8], a ret that Arxan writes so it does not look like one
static bool fake_ret(const uint8_t* p)
{
    auto a = skip_prefixes(p);

    if (!(a.rex & 8) || a.op[0] != 0x8D || a.op[1] != 0x64 || a.op[2] != 0x24 || a.op[3] != 0x08)
        return false;

    auto b = skip_prefixes(a.op + 4);
    return b.op[0] == 0xFF && b.op[1] == 0x64 && b.op[2] == 0x24 && b.op[3] == 0xF8;
}

// push r; lea r, [rip+X]; xchg [rsp], r; then ret or the fake ret above. Both land on X with the stack untouched.
static bool hidden_jump(const uint8_t* p, uint32_t ea, uint32_t& target)
{
    auto a = skip_prefixes(p);

    if (a.op[0] < 0x50 || a.op[0] > 0x57)
        return false;

    int reg = (a.op[0] & 7) | ((a.rex & 1) << 3);
    auto b = skip_prefixes(a.op + 1);

    if (!(b.rex & 8) || b.op[0] != 0x8D || (b.op[1] & 0xC7) != 0x05 || ((((b.op[1] >> 3) & 7) | ((b.rex & 4) << 1)) != reg))
        return false;

    auto lea_end = b.op + 6;
    target = ea + static_cast<uint32_t>(lea_end - p) + *reinterpret_cast<const int32_t*>(b.op + 2);

    auto c = skip_prefixes(lea_end);

    if (!(c.rex & 8) || c.op[0] != 0x87 || (c.op[1] & 0xC7) != 0x04 || c.op[2] != 0x24 || ((((c.op[1] >> 3) & 7) | ((c.rex & 4) << 1)) != reg))
        return false;

    auto d = skip_prefixes(c.op + 3);
    return d.op[0] == 0xC3 || fake_ret(c.op + 3);
}

// Walks the handler through the Arxan jumps up to its ret, collecting every direct call.
// body is the first real instruction, where the native's own code starts.
bool trace_handler(const uint8_t* base, uint32_t size, uint32_t handler, std::vector<uint32_t>& calls, uint32_t& body)
{
    uint32_t ea = handler;

    calls.clear();
    body = 0;

    for (int steps = 0; steps < 3000; steps++)
    {
        if (ea + 64ull > size || !is_readable(reinterpret_cast<uintptr_t>(base + ea), 64))
            return false;

        auto p = base + ea;
        uint32_t target = 0;

        if (hidden_jump(p, ea, target))
        {
            ea = target;
            continue;
        }

        auto len = insn_len(p);

        if (!len)
            return false;

        auto op = skip_prefixes(p).op;
        auto next = ea + static_cast<uint32_t>(len);

        if (op[0] == 0xE9)
        {
            ea = next + *reinterpret_cast<const int32_t*>(op + 1);
            continue;
        }

        if (op[0] == 0xEB)
        {
            ea = next + static_cast<int8_t>(op[1]);
            continue;
        }

        if (!body)
            body = ea;

        if (op[0] == 0xC3 || op[0] == 0xC2 || op[0] == 0xCC || fake_ret(p))
            return true;

        if (op[0] == 0xE8)
        {
            auto t = next + *reinterpret_cast<const int32_t*>(op + 1);

            if (t < size)
                calls.push_back(t);
        }

        // an indirect jmp cannot be followed statically
        if (op[0] == 0xFF && ((op[1] >> 3) & 7) == 4)
            return false;

        ea = next;
    }

    return false;
}

bool collect_natives(HMODULE game, std::vector<native_info>& out)
{
    auto base = reinterpret_cast<uintptr_t>(game);
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + reinterpret_cast<const IMAGE_DOS_HEADER*>(base)->e_lfanew);
    auto end = base + nt->OptionalHeader.SizeOfImage;

    // scrProgram native resolve loop: jbe; mov rdx, [rbx+40h]; lea rcx, [table]; mov rdx, [rdx+rdi*8]; call GetNativeHandler
    auto hit = find_pattern(base, "76 32 48 8B 53 40 48 8D 0D ?? ?? ?? ?? 48 8B 14 FA E8");

    if (!hit)
    {
        write_log(log_level::error, "native table pattern not found");
        return false;
    }

    auto table = rip_resolve(hit + 6, 3, 7);

    write_log(log_level::ok, "native table at image+0x%llX", table - base);

    size_t wrong_bucket = 0;
    size_t outside = 0;

    for (uint32_t i = 0; i < 256; i++)
    {
        uintptr_t node = 0;
        read(table + i * 8ull, node);

        for (int guard = 0; node && guard < 4096; guard++)
        {
            entry_count cnt{};

            if (!is_readable(node, 0xC4) || !read(node + 0x48, cnt))
                break;

            auto count = cnt.a ^ cnt.b ^ static_cast<uint32_t>(node + 0x48);

            if (count > 7)
            {
                write_log(log_level::warn, "bucket %u: block 0x%llX decodes to %u entries, skipped", i, node, count);
                break;
            }

            for (uint32_t j = 0; j < count; j++)
            {
                uint64_t hash = 0;
                uintptr_t handler = 0;

                decode(node + 0x54 + j * 16ull, hash);
                read(node + 0x10 + j * 8ull, handler);

                if ((hash & 0xFF) != i)
                    wrong_bucket++;

                if (handler < base || handler >= end)
                {
                    outside++;
                    handler = base;
                }

                native_info n;
                n.hash = hash;
                n.handler = handler - base;
                out.push_back(n);
            }

            uint64_t next = 0;

            if (!decode(node, next))
                break;

            node = static_cast<uintptr_t>(next);
        }
    }

    std::sort(out.begin(), out.end(), [](auto& a, auto& b) { return a.hash < b.hash; });

    write_log(log_level::ok, "natives: %zu", out.size());

    size_t traced = 0;

    for (auto& n : out)
    {
        uint32_t body = 0;

        if (n.handler && trace_handler(reinterpret_cast<const uint8_t*>(base), static_cast<uint32_t>(end - base), static_cast<uint32_t>(n.handler), n.calls, body))
            traced++;

        n.body = body;
    }

    write_log(log_level::ok, "handlers traced to their ret: %zu of %zu", traced, out.size());

    if (wrong_bucket)
        write_log(log_level::warn, "%zu hashes are in the wrong bucket, the decoding is off", wrong_bucket);

    if (outside)
        write_log(log_level::warn, "%zu handlers point outside the game image", outside);

    return !out.empty();
}

struct cross_row
{
    std::string name;
    std::string ns;
    uint64_t original;
    int command_index;
    int call_count;
};

// natives.txt comes from tools/gen_natives.py, one line per native:
// "NAME NAMESPACE command_index call_count hash_build0 hash_build1 ..."
void name_natives(std::vector<native_info>& natives, const std::wstring& path)
{
    FILE* f = nullptr;

    if (_wfopen_s(&f, path.c_str(), L"rb") || !f)
    {
        write_log(log_level::warn, "natives.txt not found, natives stay unnamed");
        return;
    }

    std::vector<cross_row> rows;
    std::vector<std::unordered_map<uint64_t, uint32_t>> cols;
    char line[4096];

    while (fgets(line, sizeof(line), f))
    {
        if (line[0] == '#')
            continue;

        char name[256]{};
        char ns[64]{};
        int index = -1;
        int count = 0;
        int used = 0;

        if (sscanf_s(line, "%255s %63s %d %d%n", name, static_cast<unsigned>(sizeof(name)), ns, static_cast<unsigned>(sizeof(ns)), &index, &count, &used) != 4)
            continue;

        cross_row r{ name[0] == '-' ? "" : name, ns[0] == '-' ? "" : ns, 0, index, count };
        auto p = line + used;

        for (size_t c = 0;; c++)
        {
            char* end = nullptr;
            auto h = _strtoui64(p, &end, 16);

            if (end == p)
                break;

            if (c >= cols.size())
                cols.emplace_back();

            if (c == 0)
                r.original = h;

            cols[c].emplace(h, static_cast<uint32_t>(rows.size()));
            p = end;
        }

        rows.push_back(std::move(r));
    }

    fclose(f);

    if (cols.empty())
    {
        write_log(log_level::warn, "natives.txt is empty");
        return;
    }

    size_t best = 0;
    size_t best_hits = 0;

    for (size_t c = 0; c < cols.size(); c++)
    {
        size_t hits = 0;

        for (auto& n : natives)
            hits += cols[c].count(n.hash);

        if (hits > best_hits)
        {
            best = c;
            best_hits = hits;
        }
    }

    write_log(log_level::ok, "crossmap: build column %zu of %zu matches %zu of %zu natives", best, cols.size(), best_hits, natives.size());

    size_t named = 0;

    for (auto& n : natives)
    {
        int64_t row = -1;
        auto it = cols[best].find(n.hash);

        if (it != cols[best].end())
            row = it->second;

        // newest column first for hashes the matched build does not list
        for (size_t c = cols.size(); row < 0 && c-- > 0;)
        {
            auto other = cols[c].find(n.hash);

            if (other != cols[c].end())
                row = other->second;
        }

        if (row < 0)
            continue;

        auto& r = rows[row];
        n.name = r.name;
        n.ns = r.ns;
        n.original = r.original;
        n.command_index = r.command_index;
        n.call_count = r.call_count;
        named += !r.name.empty();
    }

    write_log(named == natives.size() ? log_level::ok : log_level::warn, "named natives: %zu of %zu", named, natives.size());
}

// The command is the call the bank build makes to its Command* function. It is trusted only when the retail
// wrapper makes the same number of calls (debug ones excluded) and the target is not a helper many natives share,
// otherwise the command was inlined into the body.
void pick_commands(std::vector<native_info>& natives)
{
    std::unordered_map<uint32_t, uint32_t> freq;

    for (auto& n : natives)
    {
        std::vector<uint32_t> unique_calls(n.calls);
        std::sort(unique_calls.begin(), unique_calls.end());
        unique_calls.erase(std::unique(unique_calls.begin(), unique_calls.end()), unique_calls.end());

        for (auto t : unique_calls)
            freq[t]++;
    }

    size_t commands = 0;

    for (auto& n : natives)
    {
        if (n.command_index < 0 || static_cast<int>(n.calls.size()) != n.call_count)
            continue;

        auto t = n.calls[n.command_index];

        if (freq[t] > 8)
            continue;

        n.command = t;
        commands++;
    }

    write_log(log_level::ok, "command functions: %zu, inlined into the body: %zu", commands, natives.size() - commands);
}
