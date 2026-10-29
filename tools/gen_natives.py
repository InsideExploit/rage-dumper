import bisect
import collections
import ctypes
import ntpath
import os
import re
import struct
import sys
from ctypes import wintypes as w

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

# calls a final build compiles out, so they are not counted when lining the bank wrapper up with retail
debug_calls = re.compile(r'Profiler::|sysTimer|PF_|diag|Displayf|Errorf|Warningf|Assert|Printf|Debug|Logf|scrThread::|'
                         r'CScriptDebug|Verifyf|Quitf|__security', re.I)


class symbol_info(ctypes.Structure):
    _fields_ = [('SizeOfStruct', w.ULONG), ('TypeIndex', w.ULONG), ('Reserved', ctypes.c_uint64 * 2), ('Index', w.ULONG),
                ('Size', w.ULONG), ('ModBase', ctypes.c_uint64), ('Flags', w.ULONG), ('Value', ctypes.c_uint64),
                ('Address', ctypes.c_uint64), ('Register', w.ULONG), ('Scope', w.ULONG), ('Tag', w.ULONG),
                ('NameLen', w.ULONG), ('MaxNameLen', w.ULONG), ('Name', w.WCHAR * 2000)]


class symbols:
    def __init__(self, exe, base, size):
        self.dbg = ctypes.WinDLL('dbghelp')
        self.dbg.SymInitializeW.argtypes = [ctypes.c_void_p, w.LPCWSTR, w.BOOL]
        self.dbg.SymLoadModuleExW.restype = ctypes.c_uint64
        self.dbg.SymLoadModuleExW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, w.LPCWSTR, w.LPCWSTR, ctypes.c_uint64,
                                              w.DWORD, ctypes.c_void_p, w.DWORD]
        self.dbg.SymFromAddrW.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64),
                                          ctypes.POINTER(symbol_info)]

        self.h = ctypes.c_void_p(0x5241)
        self.base = base
        self.cache = {}

        # the pdb is looked up next to the exe
        self.dbg.SymSetOptions(0x2 | 0x4)
        self.dbg.SymInitializeW(self.h, os.path.dirname(os.path.abspath(exe)), False)
        self.dbg.SymLoadModuleExW(self.h, None, os.path.abspath(exe), None, base, size, None, 0)

    def name(self, rva):
        if rva not in self.cache:
            s = symbol_info()
            s.SizeOfStruct = 88
            s.MaxNameLen = 2000
            disp = ctypes.c_uint64()

            ok = self.dbg.SymFromAddrW(self.h, self.base + rva, ctypes.byref(disp), ctypes.byref(s))
            self.cache[rva] = s.Name if ok else ''

        return self.cache[rva]


def cstr(img, rva):
    end = img.find(b'\0', rva, rva + 300)
    s = img[rva:end]

    if s and all(32 <= c < 127 for c in s):
        return s.decode()

    return None


def rip_target(sb, pos, d):
    return sb + pos + 7 + struct.unpack_from('<i', d, pos + 3)[0]


# hash -> (name, namespace, command index, call count) from the bank build, where every native is registered as
# RegisterCommand(hash, handler, "NAME", "x:\...\commands_xxx.cpp", line) and the pdb names the command functions
def bank_natives(path):
    pe = pefile.PE(path, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    img = pe.get_memory_mapped_image()
    text = pe.sections[0]
    sb = text.VirtualAddress
    d = img[sb:sb + text.Misc_VirtualSize]

    names = {}
    files = []

    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', d):
        t = rip_target(sb, m.start(), d)

        if not (0 <= t < len(img)):
            continue

        s = cstr(img, t)

        if not s:
            continue

        if re.fullmatch(r'[A-Z][A-Z0-9_]{2,}', s):
            names[m.start()] = s
        elif s.lower().endswith('.cpp'):
            files.append((m.start(), s))

    files.sort()
    file_pos = [p for p, _ in files]

    # the register functions are the call targets that follow a name lea and a movabs rcx most often
    targets = collections.Counter()
    calls = []

    for m in re.finditer(rb'\xe8', d):
        i = m.start()
        blk = d[max(0, i - 0x60):i]

        if b'\x48\xb9' not in blk or b'\x4c\x8d\x05' not in blk:
            continue

        t = sb + i + 5 + struct.unpack_from('<i', d, i + 1)[0]
        targets[t] += 1
        calls.append((i, t))

    regs = {t for t, n in targets.items() if n >= 500}

    pdata = [s for s in pe.sections if s.Name.startswith(b'.pdata')][0]
    ends = {}

    for k in range(pdata.VirtualAddress, pdata.VirtualAddress + pdata.Misc_VirtualSize, 12):
        b, e, _ = struct.unpack_from('<III', img, k)
        ends[b] = e

    sym = symbols(path, base, pe.OPTIONAL_HEADER.SizeOfImage)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    out = {}
    prev = 0

    for i, t in calls:
        if t not in regs:
            continue

        lo = max(prev, i - 0x60)
        blk = d[lo:i]
        prev = i + 5

        h = None
        name = None
        handler = None

        for mm in re.finditer(rb'\x48\xb9(.{8})', blk, re.S):
            h = struct.unpack('<Q', mm.group(1))[0]

        for mm in re.finditer(rb'\x4c\x8d\x05', blk):
            name = names.get(lo + mm.start(), name)

        for mm in re.finditer(rb'\x48\x8d\x15(....)', blk, re.S):
            handler = sb + lo + mm.start() + 7 + struct.unpack('<i', mm.group(1))[0]

        if h is None or not name:
            continue

        k = bisect.bisect_right(file_pos, i) - 1
        ns = '-'

        if k >= 0:
            fname = ntpath.basename(files[k][1]).lower()[:-4]

            if fname.startswith('commands_'):
                fname = fname[9:]

            ns = 'SYSTEM' if fname == 'thread' else fname.upper()

        index = -1
        count = 0

        if handler:
            body = img[handler:ends.get(handler, handler + 0x400)]
            real = []

            for x in md.disasm(body, base + handler):
                if x.mnemonic == 'call' and x.op_str.startswith('0x'):
                    n = sym.name(int(x.op_str, 16) - base)

                    if not debug_calls.search(n):
                        real.append(n)

            count = len(real)
            index = next((j for j, n in enumerate(real) if '::Command' in n), -1)

        out[h] = (name, ns, index, count)

    return out


def crossmap(path):
    rows = []

    for line in open(path, encoding='utf-8', errors='replace'):
        h = re.findall(r'0x([0-9A-Fa-f]{16})', line)

        if h:
            rows.append([int(x, 16) for x in h])

    return rows


def main():
    if len(sys.argv) < 4:
        print('usage: gen_natives.py <out.txt> <CrossMapping_Universal.h> <bank exe, with its pdb next to it>')
        return

    rows = crossmap(sys.argv[2])
    bank = bank_natives(sys.argv[3])

    cols = len(rows[0])
    hits = [sum(r[c] in bank for r in rows) for c in range(cols)]
    col = max(range(cols), key=lambda c: hits[c])

    named = 0
    commands = 0

    with open(sys.argv[1], 'w', encoding='utf-8', newline='\n') as f:
        f.write('# name namespace command_index call_count hash_per_build...\n')

        for r in rows:
            name, ns, index, count = bank.get(r[col], ('-', '-', -1, 0))
            named += name != '-'
            commands += index >= 0
            f.write('%s %s %d %d %s\n' % (name, ns, index, count, ' '.join('%016X' % h for h in r)))

    print('%d bank natives, bank build is column %d, %d of %d rows named, %d with a separate command function'
          % (len(bank), col, named, len(rows), commands))


main()
