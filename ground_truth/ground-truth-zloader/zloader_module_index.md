# Zloader: how API hashes are tied to modules (the INDEX argument)

Reference notes for the Zloader ground truth in `ground-truth-zloader\`.
Everything here is read from the sample's listing, with addresses, and every
claim is checked by `zloader_index_evidence.py` (see "Reproducing" at the end).

| | |
|---|---|
| Sample | `4029f9fcba1c53d86f2c59f07d5657930bd5ee64cca4c5929cbd3142484e815a.exe` |
| Architecture | x86, PE32 |
| Image base | `0x03090000`, no relocation directory, so it always loads here |
| Hash | PJW/ELF, unseeded |
| Ground truth | 446 targets, 183 distinct hashes, 0 unresolved |

All addresses below are virtual addresses as Ghidra shows them.

---

## 1. The short version

Zloader does **not** pick a DLL by hashing its name. Every API lookup goes through
one resolver:

```
resolver(INDEX, HASH)      FUN_030a3170
```

- `INDEX` is a small number that selects a DLL from an **encrypted name table**.
- `HASH` is the PJW hash of the lowercased export name, looked up **only in
  that DLL**.

So for every hash constant in the binary, the code itself states which module it
belongs to. The hash is unseeded, so the module can't be recovered from the hash
alone, but the INDEX next to it settles it.

Only one module **hash** exists in the whole sample: `0x0b9f5b9c` = `KERNEL32.DLL`,
used once at bootstrap to find kernel32 before anything else is available.

---

## 2. Bootstrap: getting LoadLibraryA and GetProcAddress

`FUN_030a3850` runs first:

```
030a3854  push 0xb9f5b9c        ; module hash of "KERNEL32.DLL"
030a3859  call 0x30a3530        ; PEB lookup by module hash -> kernel32 base
030a386b  push 0xb1c1fe3        ; GetProcAddress
030a3870  push eax
030a3871  call 0x30a3620        ; export lookup in kernel32
030a3879  mov  [0x30be820], eax
030a387e  push 0x8adf2d1        ; LoadLibraryA
030a3883  push esi
030a3884  call 0x30a3620
030a3892  mov  [0x30be824], eax ; <- used later by the resolver to load DLLs
```

These three constants bypass the INDEX mechanism. They're 3 of the 446 targets.

### PEB lookup `FUN_030a3530` (module-hash path)

Walks the loader list and, for each entry:

```
030a359c  movzx esi, word [edi+0x2c]        ; BaseDllName.Length
030a35d7  movzx ebx, word [eax+esi*2+2]     ; next UTF-16 unit ...
030a35d0  mov   [ebp+esi-0x50], bl          ; ... stored as ONE byte (narrowed)
030a35fb  cmp   esi, 0x3e                   ; at most 63 characters
030a356b  call  0x3097700                   ; in place: a-z -> A-Z (via 0309d630)
030a3573  push  esi                         ; explicit length (no terminator)
030a3575  call  0x30a3140                   ; PJW hash
```

So a module hash is `PJW(UPPERCASE(name narrowed to bytes))`.

---

## 3. The resolver `FUN_030a3170(INDEX, HASH)`

### 3.1 Result cache (does not affect which module is used)

```
030a317c  mov esi, [ebp+0xc]                ; HASH
030a317f  call 0x30a6170                    ; cache size
030a318a  div ecx                           ; slot = HASH mod size
030a318c  mov eax, [edx*4 + 0x30be8a0]      ; cached key
...
030a3266  mov eax, [edi*4 + 0x30bf240]      ; cache hit -> cached address
```

On a miss, it falls through to the INDEX path below and stores the result at
`030a32ee` / `030a32f5`.

### 3.2 The INDEX path (this is the part that matters)

```
030a31fd  mov ebx, [ebp+8]                  ; INDEX
030a320a  call 0x30ab320                    ; returns 25 (table bound)
030a320f  cmp eax, ebx
030a3211  jbe 0x30a3242                     ; INDEX >= 25: no name
030a3213  mov eax, 0xfee00000
030a3218  bt  eax, ebx
030a321b  jb  0x30a3242                     ; INDEX 21,22,23,25..31: no name
030a3224  push dword [ebx*4 + 0x30bc2ec]    ; encrypted name entry for INDEX
030a322b  call 0x30a3400                    ; decrypt -> ASCII DLL name
030a323a  call 0x30a1af0                    ; copy to [ebp-0x30]

030a3244  mov ebx, [ebx*4 + 0x30be828]      ; per-INDEX handle cache
030a324b  test ebx, ebx
030a324d  jne 0x30a32a9                     ; already loaded -> use it
030a324f  cmp eax, 0x17 / je -> ebx = [0x30be818]
030a3254  cmp eax, 0x16 / je -> ebx = [0x30be814]
030a3259  cmp eax, 0x15 / jne -> load by name
030a325e  mov ebx, [0x30be810]
030a3282  lea eax, [ebp-0x30]
030a3286  call [0x30be824]                  ; LoadLibraryA(decrypted name)
030a32a2  mov [eax*4 + 0x30be828], ebx      ; cache the handle for INDEX

030a32a9  push esi                          ; HASH
030a32aa  push ebx                          ; module handle chosen by INDEX
030a32ab  call 0x30a3620                    ; export lookup in THAT module
```

Reading it in order:

1. **Bound and mask.** `0x30ab320` returns 25. The mask `0xfee00000` has bits 21–23
   and 25–31 set. So indices **0–20 and 24** have an encrypted name, and
   **21–23** do not.
2. **Name.** For a named index, the entry at `[INDEX*4 + 0x030bc2ec]` is decrypted
   by `0x30a3400`.
3. **Handle.** If the handle cache for INDEX is empty:
   - 0x15, 0x16 and 0x17 use preset handles `[0x30be810]`, `[0x30be814]` and
     `[0x30be818]`.
   - Any other index calls LoadLibraryA on the decrypted name.
4. **Lookup.** The handle and HASH go to the export lookup. **The DLL is fixed by
   INDEX alone.**

### 3.3 Export lookup `FUN_030a3620(BASE, HASH)`

```
030a36b0  movsx eax, al
030a36b4  call 0x309a690                    ; per character: A-Z -> a-z
030a36bc  mov  [ebp+edi-0x8c], al           ; build the lowered copy
030a36cd  push -1                           ; length = strlen
030a36d6  call 0x30a3140                    ; PJW hash
030a36de  cmp  eax, [ebp+0xc]               ; compare with HASH, no key, no seed
```

So an API hash is `PJW(lowercase(export name))`.

Note the opposite folding: API names are **lowercased** (`0x309a690`) and
module names are **uppercased** (`0x309d630`). Both were confirmed by running each
routine on all 256 byte values: each changes exactly 26 letters and nothing else.

### 3.4 The hash `FUN_030a3140` → `FUN_030a2df0`

```
030a314a  cmp edx, -1 / call 0x30a2fe0      ; LEN -1 -> strlen
030a315e  jmp 0x30a2df0
030a2e03  xor ebx, ebx                      ; h = 0
030a2e1c  call 0x30a5260                    ; returns 4
030a2e21  movzx esi, byte [edi]
030a2e26  shl ebx, cl / add esi, ebx        ; h = (h << 4) + c
030a2e2c  and ebx, 0xf0000000               ; g
030a2e34 .. 030a2e58                        ; h ^= g >> 24; h &= ~g  (obfuscated)
```

That is textbook PJW/ELF. Running the sample's routine on all 11,033 distinct
corpus export names gives exactly the textbook value every time.

---

## 4. The INDEX table

Decrypted by running the sample's own `0x30a3400` on each entry:

| INDEX | Module | In corpus | Call sites | Distinct hashes |
|---:|---|:-:|---:|---:|
| 0 | kernel32.dll | yes | 252 | 83 |
| 1 | user32.dll | yes | 20 | 14 |
| 2 | ntdll.dll | yes | 0 | 0 |
| 3 | shlwapi.dll | yes | 35 | 17 |
| 4 | iphlpapi.dll | yes | 0 | 0 |
| 5 | urlmon.dll | yes | 1 | 1 |
| 6 | ws2_32.dll | yes | 54 | 21 |
| 7 | crypt32.dll | yes | 0 | 0 |
| 8 | shell32.dll | yes | 3 | 1 |
| 9 | advapi32.dll | yes | 46 | 25 |
| 10 | gdiplus.dll | no | 0 | 0 |
| 11 | gdi32.dll | yes | 0 | 0 |
| 12 | ole32.dll | yes | 5 | 5 |
| 13 | psapi.dll | yes | 4 | 3 |
| 14 | cabinet.dll | no | 0 | 0 |
| 15 | imagehlp.dll | no | 0 | 0 |
| 16 | netapi32.dll | yes | 0 | 0 |
| 17 | wtsapi32.dll | yes | 0 | 0 |
| 18 | mpr.dll | yes | 0 | 0 |
| 19 | wininet.dll | yes | 21 | 10 |
| 20 | userenv.dll | yes | 2 | 2 |
| 21 | runtime handle `[0x30be810]` | – | 0 | 0 |
| 22 | runtime handle `[0x30be814]` | – | 0 | 0 |
| 23 | runtime handle `[0x30be818]` | – | 0 | 0 |
| 24 | bcrypt.dll | no | 0 | 0 |

- **Used indices:** only 11, all for DLLs that are in the corpus. The four
  DLLs missing from the corpus are never selected.
- **Indices 21–23:** their handles are stored by setter functions that write
  an argument: `0x30a3524` for 0x15, `0x309ad36` for 0x16 and `0x30a1986` for
  0x17. Which DLL they hold is decided at runtime and can't be read statically.
  No call site uses them.

---

## 5. Where INDEX and HASH come from at each call

A raw byte scan of `.text` finds **443** `CALL 030a3170`. Nothing jumps to the
resolver, and its address is never stored as data, so this is the complete set.

| | Immediate | From a getter |
|---|---:|---:|
| INDEX | 375 | 68 |
| HASH | 282 | 161 |

### Shapes found in the binary

**a. Both immediate (the common case)**

```
03091294  push 0x3a5687         ; HASH -> shell32!SHGetFolderPathW
03091299  push 8                ; INDEX 8 = shell32.dll
0309129b  call 0x30a3170
```

**b. HASH from a getter**

```
03091413  call 0x30b8000        ; getter returns 0x0d6c4b47
03091418  push eax              ; HASH -> kernel32!Process32FirstW
03091419  push 0                ; INDEX 0 = kernel32.dll
0309141b  call 0x30a3170
```

**c. Both from getters**

```
0309172c  call 0x30b75e0        ; INDEX getter -> 19 (wininet.dll)
03091731  mov  esi, eax
03091733  call 0x30b6480        ; HASH getter -> 0x0d0ca371
03091738  push eax              ; -> wininet!InternetOpenA
03091739  push esi
0309173a  call 0x30a3170
```

**d. Arguments written with `mov` instead of `push`**

```
0309c345  mov dword [esp+4], 0x35f9338   ; HASH -> kernel32!SetFilePointerEx
0309c34d  mov dword [esp], 0             ; INDEX 0
0309c354  call 0x30a3170
```

**e. INDEX parked in a stack slot first**

```
03098d24  call 0x30b0a40        ; INDEX getter -> 9 (advapi32.dll)
03098d29  mov  [ebp-0x18], eax
03098d2c  call 0x30ab490        ; HASH getter -> 0x07a1c189
03098d31  push eax              ; -> advapi32!GetSidSubAuthority
03098d32  push dword [ebp-0x18]
03098d35  call 0x30a3170
```

### What the getters are

The getters are small, heavily obfuscated functions that compute a value from
"masked" globals in `.data`. There are 98 different getters. They take no
arguments that matter, and they're deterministic:

- **No writers:** the 132 globals they read are referenced by 605 instructions
  in total, all reads. None is written and none has its address taken. No
  pointer to any of them is stored in data.
- **No relocation:** the image has no relocation directory, so nothing
  rewrites those values at load time.

So a getter's return value is a fixed constant of the binary, as an immediate
would be. It's just computed instead of encoded.

**How values were recovered.** For each call site, the evidence script decodes
backward from the call to the first instruction that produces an argument. It
then runs that setup on a fresh, unmodified copy of the image, and records
`(INDEX, HASH)` when execution reaches `030a3170`. The `setup` column of
`zloader_resolver_sites.csv` lists the exact instructions run for each site.

**Use-site convention in `targets.txt`:**

- Immediate HASH: the address of the `push imm32` or `mov [esp+4], imm32`.
- Getter HASH: the address of the `call <getter>`.

---

## 6. Results

- **All resolve:** all 443 resolver calls resolve to an export of **the
  module their INDEX selects**. That's 182 distinct hashes, plus 3 bootstrap
  constants, giving 446 targets and 183 distinct hashes.
- **Ambiguity is only cross-DLL:** without the INDEX, a corpus-wide lookup
  finds 71 calls whose hash is exported by two DLLs. That's expected for an
  unseeded hash, because the same export name in two DLLs gives the same value.
  The INDEX settles every one:

| Corpus-wide candidates | Calls | INDEX selects |
|---|---:|---|
| ws2_32.dll, wsock32.dll | 45 | ws2_32.dll |
| advapi32.dll, kernel32.dll | 21 | advapi32.dll |
| shell32.dll, shlwapi.dll | 4 | shlwapi.dll |
| advapi32.dll, kernel32.dll | 1 | kernel32.dll |

- **Never outside the candidates:** in no case does the INDEX select a DLL
  outside the corpus-wide candidates.
- **The ground-truth CSV keeps both modules:** the folder contract's generic
  code is a flat corpus sweep, so `gt_zloader.csv` lists both candidates for
  these 71 rows (`n_modules` = 2). The export name is the same either way.
  `zloader_resolver_sites.csv` records the module the code actually uses.

### Compared with the earlier extraction

The earlier `configs\zloader_targets.txt` held 193 use sites and 103 distinct
hashes. All 103 are in the new set, which adds 80 more. The earlier
extraction was incomplete, and the new set supersedes it.

---

## 7. Things that look relevant but are not

- **`FUN_030a2e70`:** walks a module's *import* descriptors and hashes raw
  (unfolded) names with the same PJW routine. Nothing calls it and no pointer
  to it is stored, so it's dead code and excluded.
- **Indices 21–23 and the four DLLs missing from the corpus:** present in the
  table, but no call site uses them.

---

## 8. Limits

- **Static, not execution:** the emulation shows what each call site
  *computes*. It does not show that every call site executes at runtime.
- **Corpus:** names resolve against the 26-DLL x86 corpus
  (`C:\dll_corpus\x86`, digest `3dc40fabe5a1843d`). A different Windows build
  could add or remove exports.

---

## 9. Reproducing

```
python3 -I zloader_index_evidence.py <sample> <x86 corpus dir> <out dir>
```

It needs `pefile`, `capstone` and `unicorn`, and runs in about 5 seconds. It writes:

| File | Contents |
|---|---|
| `zloader_module_index.csv` | One row per INDEX 0–24: name entry, decrypted module, in corpus, call sites, distinct hashes |
| `zloader_resolver_sites.csv` | One row per resolver call: call address, use site, INDEX, module, HASH, export name, where INDEX and HASH came from, corpus-wide candidates, emulated setup |
| `zloader_index_run.txt` | Log: the INDEX path disassembled from the image, the bound and mask, preset-handle writers, completeness checks, totals |

### Checking one call by hand in Ghidra

1. Go to the call, for example `0309129b`. Read the two pushed values: HASH
   `0x003a5687`, INDEX `8`.
2. INDEX 8 → table entry `[0x030bc2ec + 8*4]`. Section 4 above gives the
   decrypted name, `shell32.dll`.
3. Lowercase each candidate export name of shell32 and compute PJW. Only
   `SHGetFolderPathW` gives `0x003a5687`.
4. For a getter site, step over the `call <getter>` in a debugger, or compare
   with the `hash` column of `zloader_resolver_sites.csv`.
