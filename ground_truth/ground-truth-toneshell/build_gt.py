# ToneShell ground truth.
#
# FUN_100c84a0  export names   h = h * 0xC85E31 + byte       ASCII, case sensitive
# FUN_100c8530  module names   h = h * 0xC85E31 + code unit  lower-cased
# One unit per character, not one byte: the module routine reads word-sized
# units and never consumes the zero high bytes. Hashing the UTF-16LE byte
# stream instead gives 0xdaae4730 for kernel32.dll, not the 0xd4672bc0 the
# sample compares. The fold is inside the routine.
#
# usage: build_gt.py [corpus_dir]

import csv, hashlib, sys
from pathlib import Path
import pefile

SAMPLE = "toneshell"
BITS = 32
CORPUS = r"C:\dll_corpus\x86"
M32 = 0xFFFFFFFF
MULT = 0xC85E31
BUF = None   # no buffer constraint in this sample

# --- hash -----------------------------------------------------------------

def hash_api(name):
    h = 0
    for b in name.encode("latin-1"):
        h = (h * MULT + b) & M32
    return h

def hash_module(name):
    h = 0
    for c in name.lower():
        h = (h * MULT + ord(c)) & M32
    return h

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
            if BUF and any(len(n) > BUF for n in nlist):
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
