# Conti ground truth.
#
# FUN_00405530 is MurmurHash2A (Austin Appleby, MurmurHash2.cpp). The code
# below is transcribed from that published reference. Sample-specific values:
#   multiplier 0x5bd1e995   published Murmur2 constant
#   004055bd   MOV EDI,0x5b2d          seed
#   004055a0   fold loop, A-Z lowered
#   00405543   LEA EAX,[EBP-0x44]      64-byte stack buffer, copy unchecked,
#                                      so the sample cannot hash a name of 65+
# One routine serves both API and module names.
#
# usage: build_gt.py [corpus_dir]

import csv, hashlib, sys
from pathlib import Path
import pefile

SAMPLE = "conti"
BITS = 32
CORPUS = r"C:\dll_corpus\x86"
M32 = 0xFFFFFFFF
MULT = 0x5BD1E995
SEED = 0x5B2D
BUF = 64

# --- hash -----------------------------------------------------------------

def _mmix(h, k):
    k = (k * MULT) & M32
    k ^= k >> 24
    k = (k * MULT) & M32
    h = (h * MULT) & M32
    return h ^ k

def hash_api(name):
    d = bytes((c + 0x20) if 0x41 <= c <= 0x5A else c
              for c in name.encode("latin-1"))
    total, h, i = len(d), SEED, 0
    while total - i >= 4:
        h = _mmix(h, int.from_bytes(d[i:i + 4], "little"))
        i += 4
    tail, rem = 0, total - i
    if rem == 3: tail ^= d[i + 2] << 16
    if rem >= 2: tail ^= d[i + 1] << 8
    if rem >= 1: tail ^= d[i]
    h = _mmix(h, tail)
    h = _mmix(h, total)
    h ^= h >> 13
    h = (h * MULT) & M32
    h ^= h >> 15
    return h

MODULE_HASHES = {"": hash_api}

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
            mods.setdefault(fn(p.name), set()).add(
                f"{p.name} [{label}]" if label else p.name)
    if wrong:
        sys.exit(f"corpus is not {BITS}-bit: " + ", ".join(wrong))

    rows, unresolved, ambiguous, overlong = [], 0, 0, 0
    for site, h in targets:
        hit = api.get(h)
        if hit:
            mlist = sorted({m for m, _ in hit})
            nlist = sorted({n for _, n in hit})
            ambiguous += len(mlist) > 1
            if any(len(n) > BUF for n in nlist):
                overlong += 1
                nlist = [n + " [exceeds sample buffer]" for n in nlist]
            rows.append({"site": site, "constant": f"0x{h:08x}", "role": "API",
                         "module": "|".join(mlist), "name": "|".join(nlist),
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
    msg = (f"{SAMPLE}: {len(files)} modules, {nexp} exports, corpus {digest}, "
           f"{len(rows)} targets, {unresolved} unresolved, {ambiguous} ambiguous")
    if overlong:
        msg += f", {overlong} exceed the sample's {BUF}-byte buffer"
    print(msg)
    return 1 if unresolved else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
