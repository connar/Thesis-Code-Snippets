# Feasibility Pilot

Supporting material for the MSc thesis *Automating Malware Deobfuscation: An
Evaluation of LLM-Guided Logic Extraction and Execution* (Angelos Solomos,
TU Eindhoven).

These three experiments test the central assumption of the proposed architecture
before implementation: that emulating a resolver in isolation fails on real
malware, and that provisioning a minimal process environment makes the same
resolver succeed at a cost far below full-system emulation.

---

## Setup

| Item | Value |
|---|---|
| Sample | Netwalker |
| SHA-256 | `58e923ff158fb5aecd293b7a0e0d305296110b83c6e270786edcc4fea1c8404c` |
| Architecture | x86, 32-bit PE |
| Ghidra | 12.1.2 |
| Emulator | `EmulatorHelper` (Ghidra P-code) |
| DLL corpus | `C:\dll_corpus\x86\ntdll.dll`, copied from `C:\Windows\SysWOW64` |

The sample was reverse-engineered independently before the pilot, so the expected
results were known in advance. Its resolver operates in two stages:

| Function | Role |
|---|---|
| `FUN_00401220` | resolve a module handle by hash of the module name |
| `FUN_00401000` | resolve an export address by hash, within a given module |
| `FUN_00407990` | the hash function, called by both |
| `FUN_00413C70` | returns the PEB pointer by reading `FS:[0x30]` |

---

## Running the scripts

These are standard Ghidra scripts written in Java. Java is used rather than Python
because Ghidra 12.x does not enable a Python interpreter by default: Jython is an
optional extension, and PyGhidra requires launching Ghidra through a separate
script with a Python 3 interpreter on the path. Java scripts run with no
additional setup.

**1. Install the script.** Copy the `.java` file into Ghidra's user script
directory:

```powershell
Copy-Item PilotA.java "$env:USERPROFILE\ghidra_scripts\PilotA.java" -Force
```

On Linux or macOS the directory is `~/ghidra_scripts`.

The filename must match the public class name inside the file, or compilation
fails with *"The class could not be found."*

**2. Open the sample.** In Ghidra, create or open a project, then
**File → Import File**, select the sample, and accept the PE loader. Double-click
the imported file to open the CodeBrowser window, and let auto-analysis finish
before running anything.

**3. Run.** Open **Window → Script Manager**, click the refresh button (two green
arrows) so Ghidra picks up the new file, locate the script under the *Thesis*
category, and click the green Run button. Output appears in the console pane at
the bottom of the CodeBrowser window.

**4. Adjust addresses if needed.** Each script hardcodes the function addresses of
the sample it was written for. If a different build is used, the addresses will
differ; the constants are grouped at the top of each file for that reason. Pilot C
additionally verifies that an instruction exists at the configured address and
reports the image base if it does not.

**Editing note.** Pasting long scripts into Ghidra's built-in editor can silently
truncate them, producing *"reached end of file while parsing."* Copying the file
into `ghidra_scripts` from the command line avoids this.

---

## Pilot A — isolated emulation

**Question.** Does emulating a real resolver with no process environment fail, and
if so, how?

**Method.** Point the emulator at `FUN_00401220` with a stack frame and a non-zero
hash argument, but nothing else. Trace every instruction.

**Result.**

```
steps executed : 16
outcome        : returned normally
stopped at PC  : 00badbad
error          : null
EAX            = 0x00000000
```

Trace:

```
0000  00401220   PUSH EBP
0001  00401221   MOV EBP,ESP
0002  00401223   SUB ESP,0x10
0003  00401226   CALL 0x00413c70
0004  00413c70   PUSH EBP
0005  00413c71   MOV EBP,ESP
0006  00413c73   MOV EAX,FS:[0x30]
0007  00413c79   POP EBP
0008  00413c7a   RET
0009  0040122b   MOV dword ptr [EBP + -0xc],EAX
0010  0040122e   CMP dword ptr [EBP + -0xc],0x0
0011  00401232   JZ 0x0040128b
0012  0040128b   XOR EAX,EAX
0013  0040128d   MOV ESP,EBP
0014  0040128f   POP EBP
0015  00401290   RET
```

**What it means.** The resolver obtains its PEB pointer at instruction 6. The
emulator has no segment base, so the read returns zero. The null check at
instruction 10 fires and the function returns without ever reaching the module
list.

The important detail is the *mode* of failure. The function does not crash — it
executes a normal `RET` and returns zero. That result is indistinguishable from
"this hash matches no candidate." An analyst using isolated emulation on such a
resolver gets no indication that the missing environment, rather than the hash,
was the obstacle.

A silent wrong answer is worse than a visible failure, because it cannot be
detected from the output alone.

---

## Pilot B — module-list provisioning

**Question.** Does provisioning a minimal process environment make the same
resolver work, and how much memory does it take?

**Method.** Two stages.

Stage 1 emulates the sample's own hash function on the string `"kernel32.dll"` to
obtain a target hash. No hash database or hardcoded constant is used — the sample
acts as its own oracle.

Stage 2 writes a PEB (only `+0x0c`, the loader-data pointer), a `PEB_LDR_DATA`
(only `+0x14`, the `InMemoryOrderModuleList` head), two module-list entries with
their `DllBase` and `BaseDllName` fields, and two UTF-16 name strings. The single
call to the PEB-access helper is intercepted and answered with the synthesised PEB
address. The resolver is then run against the stage-1 hash.

**Result.**

```
stage 1: hash "kernel32.dll"
  hash = 0x6AE69F02

stage 2: provision environment, run module resolver
  provisioned 98 bytes

steps executed : 2099
PEB hooks      : 1
hash calls     : 1
outcome        : returned normally
returned       : 0x71000000
expected       : 0x71000000

MATCH - correct module base returned
```

**What it means.** 98 bytes of synthesised process state, plus one intercepted
call, convert a silent failure into a correct resolution. The structures are
synthesised rather than copied because a PEB is a runtime artefact with no
on-disk form; the *data* inside them — module names — is real.

This is the lower bound on provisioning cost for a resolver that walks the module
list. It does not cover export parsing, which Pilot C measures.

---

## Pilot C — real export table

**Question.** Can the API-resolution stage work against a real export table mapped
from disk, without any candidate list, and at what cost?

**Prerequisite.** This script reads a real system library from disk. Ghidra does
not supply one, so a copy must be placed where the script expects it. The path is
set by the `DLL_PATH` constant at the top of `PilotC.java`, which defaults to
`C:\dll_corpus\x86\ntdll.dll`:

```powershell
New-Item -ItemType Directory -Force -Path C:\dll_corpus\x86
Copy-Item C:\Windows\SysWOW64\ntdll.dll C:\dll_corpus\x86\
Get-FileHash -Algorithm SHA256 C:\dll_corpus\x86\ntdll.dll
```

The **SysWOW64** copy is required, not the System32 one. The sample is a 32-bit
binary and resolves against 32-bit libraries; the script rejects a 64-bit PE and
reports why. On a 64-bit host, `C:\Windows\System32` holds the 64-bit libraries
and `C:\Windows\SysWOW64` holds the 32-bit ones.

Record the hash of whichever copy is used. Export tables differ between Windows
builds, so the resolved address depends on the exact library version, and the
result is only reproducible if that version is known.

**Method.** Map two regions of the library at a synthesised base address: the PE
headers, and the export data region identified by `DataDirectory[0]`. Then call
`FUN_00401000(base, 0x183679F2)`.

The hash `0x183679F2` is a constant taken from the sample's own call sites. The
expected answer is computed independently by parsing the export table directly in
the script, so the test verifies itself.

**Result.**

```
file size on disk : 1822400 bytes
export dir RVA    : 0x120130, size 80181
mapped            : 84277 bytes (4.6% of the file)
exports in DLL    : 2517
expected LdrLoadDll at 0x770446F0

resolving hash 0x183679F2

steps executed : 489677
outcome        : returned normally
returned       : 0x770446F0
expected       : 0x770446F0
bytes mapped   : 84277

MATCH - correct API address returned
```

**What it means.** The resolver walked all 2,517 exports of a real system library,
hashed each name with the sample's own hash function, matched a hash the malware
itself contains, and returned the correct address.

Two properties matter:

1. **No candidate list was supplied.** The names came from the mapped library's own
   `AddressOfNames` array. This is candidate sourcing from real export tables,
   which existing tooling requires the analyst to perform manually.
2. **Only 4.6% of the file was mapped.** Mapping the entire section containing the
   export directory costs 1,260,544 bytes; mapping only the export data region
   costs 84,277. Both resolve correctly, so the smaller figure is the real
   requirement.

---

## Summary

| Configuration | Provisioned | Steps | Result |
|---|---|---|---|
| Isolated, no environment | 0 B | 16 | silent null return |
| Module resolution | 98 B | 2,099 | correct module base |
| API resolution | 84,277 B | 489,677 | correct API address |

The architecture's central assumption holds. A resolver that returns nothing under
isolated emulation resolves correctly once a minimal environment is provisioned,
and the cost is bounded at tens of kilobytes within a single static-analysis
process — several orders of magnitude below emulators that boot a full operating
system to execute one function.

---

## Cross-validation

To confirm these results reflect the approach rather than an artefact of these
scripts, the same hash computations were repeated through an independent
emulation endpoint in the GhidraMCP project:

| Input | This pilot | Independent endpoint | Steps |
|---|---|---|---|
| `"kernel32.dll"` (UTF-16, 12 chars) | `0x6AE69F02` | `0x6AE69F02` | 2,061 |
| `"ntdll.dll"` (UTF-16, 9 chars) | — | `0x84C05E40` | 1,554 |

Both agree exactly. The hash for `"ntdll.dll"` matches a module-hash constant found
at the sample's call sites, independently confirming the module identification.

---

## Scope

These experiments establish feasibility on one resolver of one sample. They are
not an evaluation. They bound the provisioning cost for a resolver that walks the
module list and parses an export directory. Resolvers that follow forwarder
chains, fall back to scanning the filesystem, or depend on state left by earlier
execution may require more, and are measured across the full corpus in the thesis
evaluation.

## Files

| File | Purpose |
|---|---|
| `PilotA.java` | isolated emulation with instruction trace |
| `PilotB.java` | module-list provisioning |
| `PilotC.java` | real export table mapping |
