# Which API hashes Emotet actually uses, and how to check one

Sample `5498779c1365116f1106813401263fc18dfed5b441dab8acccb1986dbd4e5998`,
ImageBase `0x400000`.

Emotet holds 2218 hash constants: 2216 export-name hashes in nine tables, and
2 DLL-name hashes. Of the 2216, 153 decode to a real export name; the program
calls 97 of those and never calls 56. The remaining 2063 decode to nothing.
Both DLL-name hashes resolve.

Everything below comes from one function, so read that first.

---

## 1. The resolver, and why every later step looks the way it does

`G` -> `00401230`. This is the function all nine tables call. Its arguments:

    ECX          base address of the loaded DLL
    EDX          pointer to the table of hash constants
    [EBP + 8]    how many entries that table has
    [EBP + 0xc]  the table's key
    [EBP + 0x10] the output array

The part that matters is 24 instructions long:

    00401275   MOV EDX, dword ptr [EDX + EBX*4]   next export name (EBX = export number)
    00401278   ADD EDX, ECX
    0040127A   XOR ECX, ECX                       h = 0
    0040127C   MOV AL, byte ptr [EDX]             first character
    0040127E   TEST AL, AL
    00401280   JE 0x00401296                      stop at the terminating zero
    00401282   IMUL ECX, ECX, 0x1003F             h = h * 0x1003F
    00401288   LEA EDX, [EDX + 1]                 next character
    0040128B   MOVSX EAX, AL                      sign-extend it
    0040128E   ADD ECX, EAX                       h = h + c
    00401290   MOV AL, byte ptr [EDX]
    00401292   TEST AL, AL
    00401294   JNE 0x00401282                     loop
    00401296   XOR ECX, dword ptr [EBP + 0xc]     h = h XOR key          <= (a)
    00401299   XOR ESI, ESI                       ESI = 0, table index
    0040129F   MOV EAX, dword ptr [EBP - 0xc]     EAX = the hash table
    004012A2   CMP dword ptr [EAX + ESI*4], ECX   table[ESI] == h ?      <= (b)
    004012A5   JE 0x004012AE                      match
    004012A7   INC ESI                            try the next entry
    004012A8   CMP ESI, EDI
    004012AA   JB 0x004012A2
    004012AC   JMP 0x004012DE                     no match, next export
    ...
    004012D8   MOV EAX, dword ptr [EBP + 0x10]    EAX = output array
    004012DB   MOV dword ptr [EAX + ESI*4], ECX   out[ESI] = function address  <= (c)

Three facts follow from this code.

**(a) The constants are hashed names XOR'd with the key.** The loop hashes an
export name into ECX, then `0x00401296` XORs the key into it, and only then is
ECX compared against the table. So a table entry equals
`hash(name) XOR key`. To get from a stored constant back to a hash, XOR the
key again: `hash = stored XOR key`.

**(b) ESI is the entry's position in the table.** It starts at 0 and is
incremented once per entry until `table[ESI]` matches. So when a match
happens, ESI is the index of that entry, counting from 0.

**(c) The output slot is `output_array + 4 * ESI`.** `0x004012DB` writes to
`[EAX + ESI*4]`, with EAX the output array. Four bytes per entry because these
are 32-bit pointers. So entry *n* of a table always corresponds to
`output_array + 4*n` and nowhere else.

Also note the shape of the loop. The outer loop (EBX) runs over **the DLL's
exports**, not over the table. For every export it scans the whole table. On a
match it writes a pointer; on a miss it goes to the next export and writes
nothing. The function always returns 1 and the callers do not check it. An
entry that matches no export is simply never written, and its slot keeps the
zero it has in the file.

---

## 2. The nine tables

Each table has a call site where the three stack arguments are pushed as plain
immediates. Go to the address in column 2 and you will see them.

| DLL | push site | count | key | output array | entry 0 shown as |
|---|---|---|---|---|---|
| advapi32 | `0x00407102` | 152 | `0x1A825633` | `0x004101B0` | `local_264` |
| shell32 | `0x00407996` | 218 | `0x176021C6` | `0x00410CC0` | `local_36c` |
| crypt32 | `0x00407B28` | 39 | `0x0695A091` | `0x00410410` | `local_a0` |
| urlmon | `0x00408A46` | 386 | `0x618D9E26` | `0x00411030` | `local_60c` |
| userenv | `0x00409812` | 352 | `0x1606720E` | `0x00411640` | `local_584` |
| wininet | `0x00409C50` | 107 | `0x491B67E8` | `0x00411BC0` | `local_1b0` |
| wtsapi32 | `0x0040ADBE` | 446 | `0x03BFBFC4` | `0x00411D70` | `local_6fc` |
| ntdll | `0x0040BC6F` | 180 | `0x571BDDC1` | `0x004109F0` | `local_2d4` |
| kernel32 | `0x0040C977` | 336 | `0x2068F5EB` | `0x004104B0` | `local_544` |

For example `G` -> `0040C977` shows kernel32's:

    0040C977   PUSH 0x004104B0      output array    ([EBP + 0x10])
    0040C97C   PUSH 0x2068F5EB      key             ([EBP + 0xc])
    0040C981   PUSH 0x00000150      336 entries     ([EBP + 8])
    0040C98E   CALL 0x00401230

That is where `0x2068F5EB` comes from.

### Where the constants themselves are

Just before each call, the table is built on the stack, one entry per
instruction. `G` -> `0040BCA9`:

    0040BCA9   MOV dword ptr [EBP + local_544], 0xB48D5906     entry 0
    0040BCB3   MOV dword ptr [EBP + local_540], 0x5B3BBF23     entry 1
    0040BCBD   MOV dword ptr [EBP + local_53c], ...            entry 2

Each entry goes 4 bytes further along. The constants exist only as immediate
operands inside these instructions, so they do not appear in the data section
and a search of defined data will not find them.

### Reading the stack offset, and a Ghidra quirk

Ghidra renames stack offsets to `local_XXX`, and **its number is 4 higher than
the one encoded in the instruction.** Take the first worked example below:

    0040bdcb c7 85 34 fb ff ff 4e 1a 5d 64
             MOV dword ptr [EBP + local_4d0], 0x645d1a4e

Decoding the bytes by hand: `c7 85` is `MOV dword ptr [EBP + disp32], imm32`,
so `34 fb ff ff` is the displacement, which little-endian signed is
`-0x4cc`, and `4e 1a 5d 64` is the immediate `0x645d1a4e`.

So the instruction says `EBP - 0x4cc` but Ghidra labels it `local_4d0`. The
difference is the 4 bytes of saved `EBP`: Ghidra counts from the value of
`ESP` at function entry, where `[ESP]` holds the return address, while the
instruction encodes an offset from `EBP`, which is 4 lower.

    Ghidra local_X   <->   instruction says  EBP - (X - 4)

This does not affect anything, because the index is a difference and the 4
cancels. Use whichever you can see, as long as both numbers come from the same
convention:

    index = (this offset - entry 0's offset) / 4

    with Ghidra labels   (0x544 - 0x4d0) / 4 = 0x74 / 4 = 29
    with raw disps       (0x540 - 0x4cc) / 4 = 0x74 / 4 = 29

Divide by 4 because each entry is 4 bytes. Subtract entry 0 because that is
where counting starts. The table in the previous section lists entry 0 as
Ghidra shows it, so the first form is the one to use.

Do not count instructions instead. Most of these `MOV`s are 10 bytes but some
later ones use a 7-byte form, so counting drifts. The offset is always right.

---

## 2b. How the DLL names are resolved

Emotet hashes two different kinds of name, and only one of them is in the nine
tables.

**Export names** are the 2216 table constants, covered above. They are keyed
and compared inside the resolver.

**DLL names** are handled per table, in one of two ways:

| DLL | how it is named |
|---|---|
| kernel32, ntdll | module-name hash, matched during a PEB walk |
| the other seven | a decrypted string passed to `LoadLibraryW` |

So only two DLL names are hashed. The other seven are strings that the sample
decrypts at runtime, which is why the table above can say "this table is
urlmon" without a hash being involved: the sample calls
`LoadLibraryW("urlmon.dll")`.

### The two that are hashed

`G` -> `0040C915` and `G` -> `0040BBE3`:

    0040C915   MOV ECX, 0x8F7EE672      kernel32.dll
    0040BBE3   MOV ECX, 0xD22E2014      ntdll.dll

The constant goes into ECX and is consumed by the module lookup at
`0x00401300`, which walks the loader's module list and hashes each module's
name until one matches.

The hashing routine is different from the export one. `G` -> `00401100`:

    00401100   MOVZX EAX, word ptr [ECX]    read a 16-bit code unit
    00401110   CMP AX, 0x41
    00401114   JB 0x00401124
    00401116   CMP AX, 0x5A
    0040111A   JA 0x00401124
    0040111F   ADD EAX, 0x20                A-Z folded to lower case
    00401127   IMUL EDX, EDX, 0x1003F       same multiplier
    0040112D   ADD ECX, 2                   next code unit
    00401130   ADD EDX, EAX
    0040113A   MOV EAX, EDX                 return the hash
    0040113C   RET

Three differences from the export hash:

* it reads `word ptr` and advances by 2, so it consumes one UTF-16 code unit
  per character rather than one byte
* it folds `A`-`Z` to lower case by adding `0x20`
* **no key is applied.** There is no `XOR` anywhere in it, so the constant is
  the bare hash

Checking the kernel32 one by hand, hashing the UTF-16 code units of
`kernel32.dll` (already lower case, so the fold changes nothing):

    h = 0
    h = h * 0x1003F + 'k' ... repeated for each character
    result = 0x8F7EE672

which is the constant at `0040C915`. Same for `ntdll.dll` giving
`0xD22E2014`.

### Why the CSV has only two MODULE rows

`gt_emotet.csv` has 153 rows with role `API` and 2 with role `MODULE`. The two
module rows carry `key = -` and `slot = -`, because neither applies: no key is
used, and the result is not written into a slot array, it is returned from the
lookup as the DLL's base address.

This is the difference from Latrodectus. There, all ten DLL names were hashed,
so there were ten module rows. Here only two are, so there are two. The other
seven DLL names never become hashes at all.

## 3. A hash that is used: GetProcessHeap

`G` -> `0040BDCB`

    0040BDCB   MOV dword ptr [EBP + local_4d0], 0x645d1a4e

Read two things off that line: the immediate `0x645D1A4E`, and the stack
offset `local_4d0`.

It is in the kernel32 table, so from the table above the key is `0x2068F5EB`,
entry 0 is `local_544`, and the output array is `0x004104B0`.

**The hash**, by rule (a):

    0x645D1A4E XOR 0x2068F5EB = 0x4435EFA5

**The name.** Hash every exported name of `kernel32.dll` with the loop from
section 1 and look for `0x4435EFA5`. Exactly one of the 1669 names gives it:

    GetProcessHeap

**The index**, by rule (b) and the offset arithmetic:

    0x544 - 0x4d0 = 0x74 = 116
    116 / 4 = 29

**The slot**, by rule (c):

    0x004104B0 + 4*29 = 0x004104B0 + 0x74 = 0x00410524

**Is it called?** `G` -> `00410524`, then `Ctrl+Shift+F` (References -> Show
References to Address).

72 references, all of them calls:

    004013BA   CALL dword ptr [0x00410524]
    00401437   CALL dword ptr [0x00410524]
    00401499   CALL dword ptr [0x00410524]
    ...

Double-click one to land on the call site. `GetProcessHeap` is resolved and
used 72 times.

---

## 4. A hash that is resolved but never used: Sleep

`G` -> `0040C5E1`

    0040C5E1   MOV dword ptr [EBP + local_194], 0xf8cce0fc

Same table, so same key, same entry 0, same output array.

    hash    0xF8CCE0FC XOR 0x2068F5EB = 0xD8A41517
    name    the kernel32 export hashing to 0xD8A41517 is Sleep
    index   (0x544 - 0x194) / 4 = 0x3B0 / 4 = 944 / 4 = 236
    slot    0x004104B0 + 4*236 = 0x004104B0 + 0x3B0 = 0x00410860

`G` -> `00410860`, then `Ctrl+Shift+F`.

Nothing. No `CALL dword ptr [0x00410860]` exists in the binary, and the
listing line has no `XREF` annotation. Ghidra may show undefined bytes with no
label here, because nothing in the program references the address.

`Sleep` is a real kernel32 export, the resolver does write its address into
that slot, and the program never calls it.

So "no calls" does not mean the resolution failed. The arithmetic is the same
as for `GetProcessHeap`, it lands on a real export, the slot is written, and
there is still no call. A hash being resolved and the result being used are
two separate things.

---

## 5. An entry that is not a hash at all

`G` -> `00409C7A`

    00409C7A   MOV dword ptr [EBP + local_6fc], 0x289462d3

The offset `local_6fc` is entry 0 of the wtsapi32 table, so key `0x03BFBFC4`,
output array `0x00411D70`.

    hash    0x289462D3 XOR 0x03BFBFC4 = 0x2B2BDD17
    index   (0x6fc - 0x6fc) / 4 = 0
    slot    0x00411D70 + 0 = 0x00411D70

**The name.** No name among wtsapi32's 76 exports hashes to `0x2B2BDD17`.
Neither does any name in the other eight DLLs, checked under all nine keys.
There is no name to recover.

**Is it read?** `G` -> `00411D70`, `Ctrl+Shift+F`. Nothing.

**Is it written?** This cannot be answered by looking at the slot. The only
write is `0x004012DB`,
`MOV [EAX + ESI*4], ECX`, where both the array and the index are in
registers. Ghidra cannot attribute a computed write like that to any
particular address, so no slot in any of the nine arrays has a write
cross-reference, including the slots that certainly are written.

So "never written" is not a lookup. It follows from the code: the write at
`0x004012DB` is only reached through the match at `0x004012A5`. If no export
name produces this value, the comparison at `0x004012A2` never succeeds, the
jump at `0x004012A5` is never taken, and the write never executes. The slot
keeps the zero it has in the file.

No name means no match, and no match means no write, so the slot is never
read.

---

## 6. Which table does a slot belong to?

Given a slot address, find the range that contains it. Each range is
`output array` to `output array + 4*count`.

| range | DLL | entries |
|---|---|---|
| `0x004101B0` - `0x0041040F` | advapi32 | 152 |
| `0x00410410` - `0x004104AB` | crypt32 | 39 |
| `0x004104B0` - `0x004109EF` | kernel32 | 336 |
| `0x004109F0` - `0x00410CBF` | ntdll | 180 |
| `0x00410CC0` - `0x00411027` | shell32 | 218 |
| `0x00411030` - `0x00411637` | urlmon | 386 |
| `0x00411640` - `0x00411BBF` | userenv | 352 |
| `0x00411BC0` - `0x00411D6B` | wininet | 107 |
| `0x00411D70` - `0x00412467` | wtsapi32 | 446 |

Then `index = (slot - output array) / 4`.

A few addresses between the ranges (`0x004104AC`, `0x00411028`, `0x0041102C`,
`0x00411638`, `0x0041163C`, `0x00411D6C`) are not slots. They are ordinary
globals the compiler placed between the arrays, and they do have references of
their own. Check the range before concluding anything about an address.

---

## 7. Summary of the three outcomes

| decodes to a name | has calls | meaning | count |
|---|---|---|---|
| yes | yes | resolved and used | 97 |
| yes | no | resolved, never used | 56 |
| no | no | not a hash | 2063 |

Plus the 2 module-name hashes from section 2b, which always resolve and are
always used.

`gt_emotet.csv` holds the 155 that decode to a name: 153 export hashes and 2
module-name hashes, each with its key, recovered hash, slot address, and
whether the program calls it.
