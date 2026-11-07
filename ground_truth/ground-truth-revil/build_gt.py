# REvil ground truth.
#
# FUN_00405bae  API hash (NAME), result EAX, 32 bits
#   00405bb4  PUSH 0x2b / POP EAX         h = 0x2b
#   00405bb9  IMUL EAX,EAX,0x10f
#   00405bc0  MOVZX ECX,CL                unsigned byte, no fold
#   00405bc3  ADD EAX,ECX
#   00405bc7  TEST CL,CL / JNZ            terminator not hashed
# FUN_00405dcf  resolver (X)
#   00405ddf  XOR ESI,0x76c7
#   00405de5  SHL ESI,0x10
#   00405de8  XOR ESI,[EBP+8]
#   00405deb  XOR ESI,0xafb9              v = ((X ^ 0x76c7) << 16) ^ X ^ 0xafb9
#   00405df3  SHR EAX,0x15                v >> 21 = module id
#   00405df7..00405e6d                    switch: id -> module getter, MODULE_ID
#   00405ea0  AND ESI,0x1fffff            v & 0x1fffff = API hash
#   00405edb  AND EAX,0x1fffff            mask applied by the caller of 00405bae
# Module getters: 00405cd3 / 00405d17 PUSH imm32 -> FUN_00405d54, PEB walk,
#   UTF-16 BaseDllName, A-Z folded, same hash, compared with X ^ 0x7476d3e
#   (00405d73). The other ten decrypt a name with 00404e03 and LoadLibraryA it.
# Constants: 140 dwords at 0041c9f8..0041cc27, walked by 00405bcd; 10 inline
#   PUSH 0x5c1336be (LoadLibraryA); 2 module hashes at 00405cd3, 00405d17.
# targets.txt holds the stored values; unmask() applies the decode.
#
# usage: build_gt.py [corpus_dir]

import csv, hashlib, sys
from pathlib import Path
import pefile

SAMPLE = "revil"
BITS = 32
CORPUS = r"C:\dll_corpus\x86"
M32 = 0xFFFFFFFF
MASK21 = 0x1FFFFF
PEB_SITES = {0x00405CD3, 0x00405D17}
MODULE_ID = {
    "advapi32.dll":  0x26e,
    "crypt32.dll":   0x68a,
    "gdi32.dll":     0x4db,
    "kernel32.dll":  0x0e3,
    "mpr.dll":       0x397,
    "ntdll.dll":     0x64b,
    "ole32.dll":     0x068,
    "shell32.dll":   0x7c2,
    "shlwapi.dll":   0x1e3,
    "user32.dll":    0x28d,
    "winhttp.dll":   0x05f,
    "winmm.dll":     0x6f8,
}

# --- hash -----------------------------------------------------------------

def _h(units):
    h = 0x2B
    for c in units:
        h = (h * 0x10F + c) & M32
    return h

def hash_api(name, module):
    mid = MODULE_ID.get(module.lower())
    if mid is None:
        return None
    return (mid << 21) | (_h(name.encode("latin-1")) & MASK21)

def hash_module(name):
    return _h(c | 0x20 if 0x41 <= c <= 0x5A else c
              for c in memoryview(name.encode("utf-16-le")).cast("H"))

def unmask(site, stored):
    if site in PEB_SITES:
        return stored ^ 0x7476D3E
    return ((((stored ^ 0x76C7) << 16) & M32) ^ stored ^ 0xAFB9) & M32

MODULE_HASHES = {"": hash_module}

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
