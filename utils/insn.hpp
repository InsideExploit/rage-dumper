#pragma once

#include <cstddef>
#include <cstdint>

struct insn_prefix
{
    const uint8_t* op;
    uint8_t rex;
    bool opsize;
    bool adsize;
};

// Arxan pads instructions with redundant REX and legacy prefixes in any order; only a REX right before the opcode counts
inline insn_prefix skip_prefixes(const uint8_t* code)
{
    insn_prefix r{ code, 0, false, false };

    for (int i = 0; i < 14; i++)
    {
        auto b = *r.op;

        if ((b & 0xF0) == 0x40)
        {
            r.rex = b;
        }
        else if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65)
        {
            r.rex = 0;
            r.opsize |= b == 0x66;
            r.adsize |= b == 0x67;
        }
        else
        {
            break;
        }

        r.op++;
    }

    return r;
}

// x64 instruction length, 0 when the bytes do not decode. Enough to walk compiled code, no operand decoding.
inline size_t insn_len(const uint8_t* code)
{
    auto pre = skip_prefixes(code);
    auto p = pre.op;
    bool opsize = pre.opsize;
    bool adsize = pre.adsize;
    bool rex_w = (pre.rex & 0x08) != 0;

    auto op = *p++;
    int map = 0;
    bool modrm = false;
    size_t imm = 0;
    size_t z = opsize ? 2 : 4;

    if (op == 0xC4 || op == 0xC5 || op == 0x62)
    {
        // VEX / EVEX, always in 64-bit mode
        if (op == 0xC5)
        {
            map = 1;
            p += 1;
        }
        else if (op == 0xC4)
        {
            map = p[0] & 0x1F;
            p += 2;
        }
        else
        {
            map = p[0] & 0x07;
            p += 3;
        }

        op = *p++;
        modrm = !(map == 1 && op == 0x77);

        if (map == 3 || (map == 1 && ((op >= 0x70 && op <= 0x73) || op == 0xC2 || (op >= 0xC4 && op <= 0xC6))))
            imm = 1;
    }
    else if (op == 0x0F)
    {
        op = *p++;

        if (op == 0x38)
        {
            map = 2;
            op = *p++;
            modrm = true;
        }
        else if (op == 0x3A)
        {
            map = 3;
            op = *p++;
            modrm = true;
            imm = 1;
        }
        else
        {
            map = 1;

            bool none = (op >= 0x04 && op <= 0x09) || op == 0x0B || op == 0x0E || (op >= 0x30 && op <= 0x37) ||
                op == 0x77 || (op >= 0x80 && op <= 0x8F) || op == 0xA0 || op == 0xA1 || op == 0xA2 ||
                op == 0xA8 || op == 0xA9 || op == 0xAA || (op >= 0xC8 && op <= 0xCF);

            modrm = !none;

            if (op >= 0x80 && op <= 0x8F)
                imm = 4;
            else if ((op >= 0x70 && op <= 0x73) || op == 0xA4 || op == 0xAC || op == 0xBA || op == 0xC2 ||
                (op >= 0xC4 && op <= 0xC6) || op == 0x0F)
                imm = 1;
        }
    }
    else
    {
        if (op < 0x40)
        {
            auto lo = op & 7;

            if (lo < 4)
                modrm = true;
            else if (lo == 4)
                imm = 1;
            else if (lo == 5)
                imm = z;
            else
                return 0;
        }
        else if (op < 0x60)
        {
        }
        else if (op == 0x63)
        {
            modrm = true;
        }
        else if (op == 0x68)
        {
            imm = z;
        }
        else if (op == 0x69)
        {
            modrm = true;
            imm = z;
        }
        else if (op == 0x6A || (op >= 0x70 && op <= 0x7F) || (op >= 0xB0 && op <= 0xB7) || op == 0xA8 || op == 0xCD ||
            (op >= 0xE0 && op <= 0xE7) || op == 0xEB)
        {
            imm = 1;
        }
        else if (op == 0x6B || op == 0x80 || op == 0x83 || op == 0xC0 || op == 0xC1 || op == 0xC6)
        {
            modrm = true;
            imm = 1;
        }
        else if (op >= 0x6C && op <= 0x6F)
        {
        }
        else if (op == 0x81 || op == 0xC7)
        {
            modrm = true;
            imm = z;
        }
        else if (op >= 0x84 && op <= 0x8F)
        {
            modrm = true;
        }
        else if (op >= 0x90 && op <= 0x9F)
        {
            if (op == 0x9A)
                return 0;
        }
        else if (op >= 0xA0 && op <= 0xA3)
        {
            imm = adsize ? 4 : 8;
        }
        else if (op == 0xA9)
        {
            imm = z;
        }
        else if (op >= 0xA4 && op <= 0xAF)
        {
        }
        else if (op >= 0xB8 && op <= 0xBF)
        {
            imm = rex_w ? 8 : z;
        }
        else if (op == 0xC2 || op == 0xCA)
        {
            imm = 2;
        }
        else if (op == 0xC8)
        {
            imm = 3;
        }
        else if (op == 0xC3 || op == 0xC9 || op == 0xCB || op == 0xCC || op == 0xCF || op == 0xD7 || op == 0xF1 ||
            (op >= 0xF4 && op <= 0xF5) || (op >= 0xF8 && op <= 0xFD) || (op >= 0xEC && op <= 0xEF))
        {
        }
        else if ((op >= 0xD0 && op <= 0xD3) || (op >= 0xD8 && op <= 0xDF) || op == 0xF6 || op == 0xF7 || op == 0xFE || op == 0xFF)
        {
            modrm = true;
        }
        else if (op == 0xE8 || op == 0xE9)
        {
            imm = 4;
        }
        else
        {
            return 0;
        }
    }

    if (modrm)
    {
        auto m = *p++;
        auto mod = m >> 6;
        auto rm = m & 7;
        auto reg = (m >> 3) & 7;

        // test r/m, imm is the only member of the F6/F7 group with an immediate
        if (map == 0 && (op == 0xF6 || op == 0xF7) && reg < 2)
            imm = op == 0xF6 ? 1 : z;

        if (mod != 3)
        {
            if (rm == 4)
            {
                auto sib = *p++;

                if (mod == 0 && (sib & 7) == 5)
                    p += 4;
            }

            if (mod == 0 && rm == 5)
                p += 4;
            else if (mod == 1)
                p += 1;
            else if (mod == 2)
                p += 4;
        }
    }

    p += imm;

    auto len = static_cast<size_t>(p - code);
    return len <= 15 ? len : 0;
}
