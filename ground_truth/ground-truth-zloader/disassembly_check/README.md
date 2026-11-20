# Zloader: why the agent found 103 of 183 constants

The ground truth for Zloader has 183 distinct constants at 446 use sites, from
443 calls to the resolver `FUN_030a3170`. In the evaluation the agent found 103
constants at 193 use sites, and the resolver named all 103 correctly.

## What we checked

1. Ghidra's cross-references to `0x030a3170` (`get_xrefs_to`, no limit) report
   190 calls. The agent finds use sites through these cross-references.
2. A follow-up run with a prompt that told the agent to visit every
   cross-reference found the same 103 constants. It reported 193 resolver call
   sites in the binary and 193 visited.
3. `CountResolverCalls.java` scans the raw bytes of every executable section for
   x86 `CALL` instructions (opcode `E8` and a 32-bit relative offset) whose
   target is `0x030a3170`, and asks Ghidra whether each one has been
   disassembled and whether it lies inside a function.

## Output

```
calls to resolver in bytes:          443
analysed, inside a function:         180
analysed, but outside any function:  14
in bytes Ghidra never disassembled:  249
first few not disassembled: [0309167b, 03091698, 03092314, 0309233a, 0309236f,
                             030923a7, 030925e9, 03092635, 0309264c, 0309267d]
```

The byte scan finds the same 443 calls the ground truth lists. 249 of them are
in bytes Ghidra's auto-analysis never disassembled, so no cross-reference
exists for them and the agent could not see them. The missing constants are a
limitation of the disassembly the agent works from, not of the resolver.

## Running it

In Ghidra, with the Zloader sample open: Window > Script Manager > New > Java,
name it `CountResolverCalls`, paste the file and run. The script only reads the
program.
