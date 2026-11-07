# NetWalker ground truth.
#
# FUN_00407890  API hash, cdecl (NAME, LEN, FOLD), result EAX
#   004078a3  MOV [EBP-4],0xffffffff      init
#   004078b4  CALL 00406bf0               LEN 0 -> strlen, terminator excluded
#   004078df  MOVSX ECX,byte ptr [EAX]    signed byte
#   004078f5  CALL 00406d10               FOLD: A-Z +0x20
#   00407906  XOR EDX,[EBP-0x10]
#   0040790c  MOV [EBP-0xc],7             8 bit-steps per character
#   00407937  AND EAX,0xedb88320
#   00407948  NOT EAX
# FUN_00407950  wrapper, FOLD 0, LEN 0
# FUN_00407990  module hash, cdecl (NAME, LEN, FOLD), same loop
#   004079df  MOVZX EDX,word ptr [ECX+EAX*2]   UTF-16 unit
#   004079f7  CALL 00406d40               FOLD: A-Z +0x20
#   00407a08  XOR ECX,[EBP-0x10]          whole unit, then 8 bit-steps
# FUN_00401220  PEB lookup
#   00401259  PUSH 1                      FOLD 1
#   0040125e  MOVZX ECX,[EAX+0x2c] / SHR ECX,1   LEN = BaseDllName.Length/2
#   00401268  MOV EAX,[EDX+0x30]          BaseDllName.Buffer
# FUN_00401000  export lookup (BASE, HASH), unseeded
#   004010a6  CALL 00407950
#   004010ae  CMP EAX,[EBP+0xc]           no key
# Constants: PUSH imm32 before CALL 00401220 (9) and CALL 00401000 (150).
#
# usage: build_gt.py [corpus_dir]

import csv, hashlib, sys
from pathlib import Path
import pefile

SAMPLE = "netwalker"
BITS = 32
CORPUS = r"C:\dll_corpus\x86"
M32 = 0xFFFFFFFF
POLY = 0xEDB88320

# --- hash -----------------------------------------------------------------

def _crc(units):
    h = 0xFFFFFFFF
    for c in units:
        h = (h ^ c) & M32
        for _ in range(8):
            h = (h >> 1) ^ (POLY if h & 1 else 0)
    return ~h & M32

def hash_api(name, module):
    return _crc(c - 0x100 if c > 0x7F else c for c in name.encode("latin-1"))

def hash_module(name):
    return _crc(c + 0x20 if 0x41 <= c <= 0x5A else c
                for c in memoryview(name.encode("utf-16-le")).cast("H"))

def unmask(site, stored):
    return stored

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
