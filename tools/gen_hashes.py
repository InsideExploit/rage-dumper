import re
import sys

import pefile


def joaat(s, lower):
    h = 0

    for c in s:
        if lower and 65 <= c <= 90:
            c += 32

        h = (h + c) & 0xFFFFFFFF
        h = (h + (h << 10)) & 0xFFFFFFFF
        h ^= h >> 6

    h = (h + (h << 3)) & 0xFFFFFFFF
    h ^= h >> 11
    h = (h + (h << 15)) & 0xFFFFFFFF
    return h


def strings(path):
    pe = pefile.PE(path, fast_load=True)
    out = set()

    for sec in pe.sections:
        if sec.Characteristics & 0x20000000:
            continue

        for m in re.finditer(rb'[\x20-\x7e]{2,255}(?=\0)', sec.get_data()):
            out.add(m.group())

    return out


def main():
    if len(sys.argv) < 3:
        print('usage: gen_hashes.py <out.txt> <exe> [exe...]')
        return

    names = set()

    for path in sys.argv[2:]:
        names |= strings(path)

    table = {}

    # exact-case hashes win over lowercase ones on collision
    for lower in (False, True):
        for s in sorted(names):
            table.setdefault(joaat(s, lower), s)

    with open(sys.argv[1], 'w', encoding='utf-8', newline='\n') as f:
        for h in sorted(table):
            f.write('%08X %s\n' % (h, table[h].decode('ascii')))

    print('%d strings, %d hashes' % (len(names), len(table)))


main()
