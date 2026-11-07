# Latrodectus ground truth.
#
# FUN_180006a14:
#   180006a7b  XOR EAX,0xedb88320          reversed CRC-32 polynomial
#   180006aaf  MOV [RSP+0x8],0xffffffff    init
#   180006ad5  SHR EAX,0x8
#   180006af7  XOR EAX,[RDX+RCX*4]         table[(byte ^ crc) & 0xff]
#   180006b04  NOT EAX                     final complement
# Standard poly, init and complement: CRC-32 as published, so zlib is used.
#
# API            ASCII, case sensitive, terminator excluded
# module, PEB    UTF-16LE, lowercased by FUN_18000bb0c, length wcslen<<1
# module, dir    UTF-16LE, no fold, name as on disk
#
# usage: build_gt.py [corpus_dir]

import csv, hashlib, sys, zlib
from pathlib import Path
import pefile

SAMPLE = "latrodectus"
BITS = 64
CORPUS = r"C:\dll_corpus\x64"
M32 = 0xFFFFFFFF

# --- hash -----------------------------------------------------------------

def hash_api(name):
    return zlib.crc32(name.encode("latin-1")) & M32

MODULE_HASHES = {
    "folded":     lambda n: zlib.crc32(n.lower().encode("utf-16-le")) & M32,
    "as on disk": lambda n: zlib.crc32(n.encode("utf-16-le")) & M32,
}

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
        site, _, h = line.partition(":")
        targets.append((site, int(h, 16)))

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
            api.setdefault(hash_api(n), set()).add((p.name, n))
        for label, fn in MODULE_HASHES.items():
            mods.setdefault(fn(p.name), set()).add(f"{p.name} [{label}]")
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
