# Emotet ground truth.
#
# Hash, read off the loop inlined at 0040127A:
#     h = h * 0x1003F + (signed char)c        SDBM, multiplier 65599
#     terminator not hashed; MOVSX makes the character signed
# Module-name variant at 00401100: UTF-16 code units, A-Z folded by +0x20.
#
# The constants are not data: nine per-module tables are built at runtime by
# runs of MOV dword ptr [EBP+disp],imm32, so each is an immediate in the
# instruction stream and targets.txt records the MOV's address. Each table is
# XORed with its own key:
#
#     stored_constant = SDBM(export_name) ^ table_key
#
# Resolution is per module and cannot be ambiguous: a table belongs to one DLL.
#
# Resolver at 0x401230. Its outer loop runs over the DLL's exports, not over
# table entries: for each export it searches the table (0x4012A2-0x4012AA) and
# on a match writes the pointer to out_array[index] (0x4012DB). On a miss it
# advances to the next export (0x4012DE). It always returns 1 (0x4012EF).
#
# 153 of the 2216 constants match an export of their table's DLL. The other
# 2063 match nothing, are never written and never read. TUTORIAL.md has the
# evidence and a worked example of each case.
#
# usage: build_gt.py [corpus_dir]

import csv, hashlib, sys
from pathlib import Path
import pefile

SAMPLE = "emotet"
BITS = 32
CORPUS = r"C:\dll_corpus\x86"
M32 = 0xFFFFFFFF
MULT = 0x1003F

# module, first table instruction, entries, XOR key, out-array base
TABLES = [
    ("advapi32", 0x00406B3A, 152, 0x1A825633, 0x004101B0),
    ("shell32",  0x0040713A, 218, 0x176021C6, 0x00410CC0),
    ("crypt32",  0x004079CF,  39, 0x0695A091, 0x00410410),
    ("urlmon",   0x00407B5A, 386, 0x618D9E26, 0x00411030),
    ("userenv",  0x00408A7A, 352, 0x1606720E, 0x00411640),
    ("wininet",  0x0040984A, 107, 0x491B67E8, 0x00411BC0),
    ("wtsapi32", 0x00409C7A, 446, 0x03BFBFC4, 0x00411D70),
    ("ntdll",    0x0040B5B9, 180, 0x571BDDC1, 0x004109F0),
    ("kernel32", 0x0040BCA9, 336, 0x2068F5EB, 0x004104B0),
]

# Two DLL names are themselves resolved by hash, through a PEB walk rather
# than LoadLibraryW. The constant is loaded into ECX and consumed by the
# module lookup at 0x00401300; the module-name hash routine is 0x00401100.
# No key is applied to these: the comparison is against the bare hash.
#   0040C915  MOV ECX, 0x8F7EE672   -> kernel32.dll
#   0040BBE3  MOV ECX, 0xD22E2014   -> ntdll.dll
# The other seven DLLs are named by a decrypted string passed to LoadLibraryW,
# so no hash is involved and there is nothing to resolve for them.
MODULE_HASH_SITES = {0x0040C915, 0x0040BBE3}

# Resolved slots that no instruction ever reads. From the liveness pass: the
# slot is written by the resolver but appears in no CALL dword ptr [slot].
RESOLVED_UNUSED_SLOTS = {
    0x004101EC, 0x0041021C, 0x00410268, 0x00410270, 0x00410280, 0x0041028C,
    0x00410294, 0x004102BC, 0x004102D4, 0x00410314, 0x00410328, 0x0041038C,
    0x004103C0, 0x00410520, 0x0041052C, 0x00410548, 0x0041055C, 0x0041056C,
    0x004105A4, 0x00410698, 0x004106BC, 0x0041070C, 0x00410730, 0x00410794,
    0x004107A4, 0x004107B0, 0x004107E4, 0x00410804, 0x0041080C, 0x00410814,
    0x0041083C, 0x00410860, 0x00410874, 0x004108A8, 0x004108B4, 0x004108CC,
    0x004108D4, 0x00410944, 0x00410950, 0x00410978, 0x0041099C, 0x004109A0,
    0x004109C8, 0x00410A5C, 0x00410A60, 0x00410C94, 0x00411BC8, 0x00411C20,
    0x00411C40, 0x00411CBC, 0x00411CC8, 0x00411D0C, 0x00411D18, 0x00411D28,
    0x00411F8C, 0x00412090,
}

# --- hash -----------------------------------------------------------------

def hash_api(name):
    h = 0
    for byte in name.encode("latin-1"):
        c = byte - 256 if byte > 127 else byte
        h = (h * MULT + c) & M32
    return h

def hash_module(name):
    h = 0
    for ch in name:
        c = ord(ch)
        if 0x41 <= c <= 0x5A:
            c += 0x20
        h = (h * MULT + c) & M32
    return h

def decode(stored, key):
    """Undo the per-table XOR: the stored immediate is SDBM(name) ^ key."""
    return stored ^ key

# --- generic --------------------------------------------------------------

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
        targets.append((int(site, 16), site, int(h, 16)))

    pin, nexp, per_mod = [], 0, {}
    for mod, base, count, key, out in TABLES:
        f = corpus / f"{mod}.dll"
        if not f.is_file():
            sys.exit(f"corpus is missing {f.name}")
        names, bits = exports_of(f)
        if bits != BITS:
            sys.exit(f"{f.name} is {bits}-bit, expected {BITS}")
        nexp += len(names)
        pin.append(f.name + hashlib.sha256(f.read_bytes()).hexdigest())
        t = {}
        for n in names:
            t.setdefault(hash_api(n), set()).add(n)
        t.setdefault(hash_module(f.name), set()).add(f.name)
        per_mod[mod] = t

    # module-name hashes: no key, hashed with the module routine, matched
    # against the corpus file names
    rows, used, unused, excluded = [], 0, 0, 0
    modnames = {}
    for f in sorted(corpus.iterdir()):
        if f.suffix.lower() in (".dll", ".drv", ".exe"):
            modnames.setdefault(hash_module(f.name), set()).add(f.name)
    for addr, site, stored in targets:
        if addr not in MODULE_HASH_SITES:
            continue
        hit = modnames.get(stored)
        if not hit:
            excluded += 1
            continue
        used += 1
        rows.append({
            "site": site, "constant": f"0x{stored:08x}", "role": "MODULE",
            "module": "-", "name": "|".join(sorted(hit)), "n_modules": 0,
            "key": "-", "hash": f"0x{stored:08x}", "slot": "-",
            "called_by_program": "yes"})

    # assign each remaining constant to its table by address, then to its slot
    by_table = {m: [] for m, *_ in TABLES}
    order = sorted(TABLES, key=lambda t: t[1])
    for addr, site, stored in targets:
        if addr in MODULE_HASH_SITES:
            continue
        owner = None
        for mod, base, count, key, out in order:
            if addr >= base and (owner is None or base > owner[1]):
                owner = (mod, base, count, key, out)
        by_table[owner[0]].append((site, stored))
    for mod, base, count, key, out in TABLES:
        for index, (site, stored) in enumerate(by_table[mod]):
            slot = out + 4 * index
            hit = per_mod[mod].get(decode(stored, key))
            if not hit:
                excluded += 1
                continue
            is_used = slot not in RESOLVED_UNUSED_SLOTS
            used += is_used
            unused += not is_used
            rows.append({
                "site": site, "constant": f"0x{stored:08x}",
                "role": "MODULE" if f"{mod}.dll" in hit else "API",
                "module": f"{mod}.dll", "name": "|".join(sorted(hit)),
                "n_modules": 1,
                "key": f"0x{key:08x}", "hash": f"0x{decode(stored, key):08x}",
                "slot": f"0x{slot:08x}",
                "called_by_program": "yes" if is_used else "no"})

    with open(here / f"gt_{SAMPLE}.csv", "w", newline="") as f:
        w = csv.DictWriter(f, ["site", "constant", "role", "module", "name",
                               "n_modules", "key", "hash", "slot",
                               "called_by_program"])
        w.writeheader(); w.writerows(rows)

    digest = hashlib.sha256("".join(sorted(pin)).encode()).hexdigest()[:16]
    print(f"{SAMPLE}: {len(TABLES)} modules, {nexp} exports, corpus {digest}, "
          f"{len(targets)} constants "
          f"({len(MODULE_HASH_SITES)} module-name hashes, "
          f"{len(targets) - len(MODULE_HASH_SITES)} in the nine tables)")
    print(f"  ground truth : {len(rows)} resolve "
          f"({used} called by the program, {unused} resolved but never read)")
    print(f"  excluded     : {excluded} match no export, never written, never read")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
