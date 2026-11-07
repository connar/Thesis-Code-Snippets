# AgentTesla shellcode ground truth.
#
# cwlkewfbz_023B0000.bin: raw 32-bit shellcode, no PE header, dumped from
# 0x023b0000. Addresses below are offsets, as Ghidra shows them at base 0.
#
# FUN_00000005  API hash, stdcall (NAME), result EAX
#   0000000c  MOV EDX,0x2326              h = 0x2326
#   00000022  MOVSX EDI,byte ptr [ESI]    signed byte, no fold
#   00000025  MOV EAX,EDX / TEST EDI,EDI  returns before the terminator
#   00000014  MOV ECX,EDX
#   00000016  SHR EAX,1                   h >> 1
#   00000018  SHL ECX,7                   h << 7
#   0000001c  OR ECX,EAX
#   0000001e  ADD ECX,EDI                 + c
#   00000020  ADD EDX,ECX                 h += ((h << 7) | (h >> 1)) + c
# FUN_00000073  export lookup (BASE, HASH), unseeded
#   000000ae  CALL 00000005
#   000000b3  CMP EAX,[EBP+0xc]           no key
# Modules are not hashed. BASE is the third loader entry (FUN_0000005f, or
# the same walk inline at 00000142 / 00000181), or LoadLibraryW on a stack
# string: Shlwapi.dll (00000280, 000003ec), Shell32.dll (00000683, 0000069a),
# Advapi32.dll (00000702 .. 00000747).
# Constants: PUSH imm32 before 55 CALL 00000073. The 56th, 0000167f, passes
# its HASH as a parameter and has no constant.
#
# usage: build_gt.py [corpus_dir]

import csv, hashlib, sys
from pathlib import Path
import pefile

SAMPLE = "agenttesla"
BITS = 32
CORPUS = r"C:\dll_corpus\x86"
M32 = 0xFFFFFFFF
INIT = 0x2326

# --- hash -----------------------------------------------------------------

def hash_api(name, module):
    h = INIT
    for c in name.encode("latin-1"):
        c = c - 0x100 if c > 0x7F else c
        h = (h + ((((h << 7) | (h >> 1)) & M32) + c)) & M32
    return h

def unmask(site, stored):
    return stored

MODULE_HASHES = {}

# --- generic --------------------------------------------------------------

SUFFIXES = (".dll", ".drv", ".exe", ".ocx", ".cpl")

def exports_of(path):
    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    d = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    names = [s.name.decode("latin-1") for s in d.symbols if s.name] if d else []
    bits = 64 if pe.FILE_HEADER.Machine == 0x8664 else 32
    pe.close()
    return names, bits

def main(argv):
    here = Path(__file__).resolve().parent
    corpus = Path(argv[0]) if argv else Path(CORPUS)
    if not corpus.is_dir():
        sys.exit(f"corpus directory not found: {corpus}\n"
                 f"usage: build_gt.py [corpus_dir]")

    targets = []
    for line in (here / "targets.txt").read_text().split():
        site, _, v = line.partition(":")
        targets.append((site, unmask(int(site, 16), int(v, 16))))

    files = sorted(p for p in corpus.iterdir() if p.suffix.lower() in SUFFIXES)
    if not files:
        sys.exit(f"no PE files under {corpus}")

    api, mods, pin, wrong, nexp = {}, {}, [], [], 0
    for p in files:
        names, bits = exports_of(p)
        if bits != BITS:
            wrong.append(f"{p.name} is {bits}-bit")
        nexp += len(names)
        pin.append(p.name + hashlib.sha256(p.read_bytes()).hexdigest())
        for n in names:
            api.setdefault(hash_api(n, p.name), set()).add((p.name, n))
        for label, fn in MODULE_HASHES.items():
            mods.setdefault(fn(p.name), set()).add(
                f"{p.name} [{label}]" if label else p.name)
    if wrong:
        sys.exit(f"corpus is not {BITS}-bit: " + ", ".join(wrong))

    rows, unresolved, ambiguous = [], 0, 0
    for site, h in targets:
        hit = api.get(h)
        if hit:
            mlist = sorted({m for m, _ in hit})
            ambiguous += len(mlist) > 1
            rows.append({"site": site, "constant": f"0x{h:08x}", "role": "API",
                         "module": "|".join(mlist),
                         "name": "|".join(sorted({n for _, n in hit})),
                         "n_modules": len(mlist)})
        elif h in mods:
            rows.append({"site": site, "constant": f"0x{h:08x}",
                         "role": "MODULE", "module": "-",
                         "name": "|".join(sorted(mods[h])), "n_modules": 0})
        else:
            unresolved += 1
            rows.append({"site": site, "constant": f"0x{h:08x}", "role": "",
                         "module": "", "name": "UNRESOLVED", "n_modules": 0})

    with open(here / f"gt_{SAMPLE}.csv", "w", newline="") as f:
        w = csv.DictWriter(f, ["site", "constant", "role", "module", "name",
                               "n_modules"])
        w.writeheader(); w.writerows(rows)

    digest = hashlib.sha256("".join(sorted(pin)).encode()).hexdigest()[:16]
    print(f"{SAMPLE}: {len(files)} modules, {nexp} exports, corpus {digest}, "
          f"{len(rows)} targets, {unresolved} unresolved, {ambiguous} ambiguous")
    return 1 if unresolved else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
