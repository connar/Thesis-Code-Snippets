# LockBit 3.0 ground truth.
#
# FUN_004011a0  API hash, args (NAME, SEED), result EAX
#   004011a8  MOV EDX,[EBP+0xc]           h = seed
#   004011ae  LODSB                       ASCII byte, zero-extended
#   004011bd  ADD DH,CL / SUB DH,CL       no-op
#   004011c3  MOV ECX,6 / LEA ECX,[ECX*2+1]   13
#   004011cf  ROR EDX,CL
#   004011d1  ADD EDX,EAX
#   004011d4  TEST EAX,EAX / JNZ          terminator hashed, no fold
# FUN_004011e4  module hash, same args and loop
#   004011f2  LODSW                       UTF-16 code unit
#   004011f5  CMP AX,0x41 .. OR AX,0x20   A-Z folded
#
# seed_mode MODULE_HASH, FUN_004079a8:
#   00407a40  PUSH 0                      module hash seeded with 0
#   00407a42  PUSH [EDI+4]                LDR entry BaseDllName.Buffer
#   00407a66  MOVD EAX,MM1 / PUSH EAX     module hash seeds the API hash
#   00407a74  CMP EAX,[EBP+8]
# FUN_00407ae0 matches the module hash against FindFirstFileW cFileName
# under <system dir>\*.dll, then *.drv; 00407bc2 PUSH 0 / 00407bcb CALL 004011e4.
#
# Key 0x4506dfca, 00407c66 XOR EAX,0x4506dfca.
#   00407c5c  table: module hash, API hashes, 0xcccccccc terminator
#   004082bb..004083ed  19 tables, 00407da4..0040824f
#   004079ba 004079e2 00407af3 00407b1b 00407b43 00408256 00408295 0040d2f5
#             MOV EAX,imm32 / XOR EAX,0x4506dfca / CALL 004079a8
# targets.txt holds the stored values; KEY is applied below.
#
# usage: build_gt.py [corpus_dir]

import csv, hashlib, sys
from pathlib import Path
import pefile

SAMPLE = "lockbit"
BITS = 32
CORPUS = r"C:\dll_corpus\x86"
M32 = 0xFFFFFFFF
KEY = 0x4506DFCA

# --- hash -----------------------------------------------------------------

def _ror13_add(units, h):
    for c in units:
        h = ((((h >> 13) | (h << 19)) & M32) + c) & M32
    return h

def hash_module(name):
    units = [c | 0x20 if 0x41 <= c <= 0x5A else c
             for c in memoryview(name.encode("utf-16-le")).cast("H")]
    return _ror13_add(units + [0], 0)

def hash_api(name, module):
    return _ror13_add(list(name.encode("latin-1")) + [0], hash_module(module))

def unmask(site, stored):
    return stored ^ KEY

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
