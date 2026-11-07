# Zloader ground truth.
#
# FUN_030a3140  hash (NAME, LEN), LEN -1 -> strlen 030a2fe0, tail-jumps 030a2df0
#   030a2e03  XOR EBX,EBX                 h = 0
#   030a2e1c  CALL 030a5260 -> CL = 4
#   030a2e21  MOVZX ESI,byte ptr [EDI]
#   030a2e26  SHL EBX,CL / ADD ESI,EBX    h = (h << 4) + c
#   030a2e2c  AND EBX,0xf0000000          g
#   030a2e34..030a2e58                    h ^= g >> 24; h &= ~g (obfuscated)
# FUN_030a3620  export lookup (BASE, HASH)
#   030a36b4  CALL 0309a690 per char      A-Z -> a-z
#   030a36cd  PUSH -1                     length by strlen, terminator excluded
#   030a36de  CMP EAX,[EBP+0xc]           unseeded, no key
# FUN_030a3530  PEB lookup (HASH)
#   030a35d7  MOVZX EBX,word [EAX+ESI*2+2]   UTF-16 unit narrowed to a byte
#   030a35fb  CMP ESI,0x3e                at most 63 characters
#   030a356b  CALL 03097700 -> 0309d630   a-z -> A-Z in place
#   030a3573  PUSH ESI                    explicit length
# FUN_030a3170  resolver (INDEX, HASH): INDEX selects an encrypted name at
#   [INDEX*4+0x030bc2ec], decrypted by 030a3400; HASH goes to 030a3620.
# Constants: arg 2 of 443 CALL 030a3170. 282 are PUSH/MOV imm32; 161 are the
#   return of a per-site getter, recorded at the getter CALL and recovered by
#   running that getter on the unmodified image (its globals are never written).
#   030a3854 PUSH 0x0b9f5b9c -> 030a3530; 030a386b, 030a387e -> 030a3620.
#
# usage: build_gt.py [corpus_dir]

import csv, hashlib, sys
from pathlib import Path
import pefile

SAMPLE = "zloader"
BITS = 32
CORPUS = r"C:\dll_corpus\x86"
M32 = 0xFFFFFFFF

# --- hash -----------------------------------------------------------------

def _pjw(units):
    h = 0
    for c in units:
        h = ((h << 4) + c) & M32
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
            h &= ~g & M32
    return h

def hash_api(name, module):
    return _pjw(c + 0x20 if 0x41 <= c <= 0x5A else c for c in name.encode("latin-1"))

def hash_module(name):
    units = [c & 0xFF for c in memoryview(name.encode("utf-16-le")).cast("H")][:63]
    return _pjw(c - 0x20 if 0x61 <= c <= 0x7A else c for c in units)

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
