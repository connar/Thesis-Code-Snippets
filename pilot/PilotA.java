// Pilot A: emulate the module resolver in isolation, with no process
// environment provisioned. Traces every instruction so the exit path is visible.
//
// Sample: Netwalker, SHA-256 58e923ff158fb5aecd293b7a0e0d305296110b83c6e270786edcc4fea1c8404c
//
//@category Thesis
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.math.BigInteger;

public class PilotA extends GhidraScript {

    // FUN_00401220: resolves a loaded module handle by hash of its name
    private static final long MODULE_RESOLVER = 0x00401220L;

    // Arbitrary non-zero argument. The value is irrelevant: the module list is
    // walked before any hash comparison, so the walk is reached regardless.
    private static final long ARG_HASH       = 0xAABBCCDDL;
    private static final int  NUM_STACK_ARGS = 1;

    private static final long STACK       = 0x00300000L;
    private static final long SENTINEL    = 0x00BADBADL;  // fake return address
    private static final int  MAX_STEPS   = 200000;
    private static final int  TRACE_LIMIT = 120;

    public void run() throws Exception {

        EmulatorHelper emu = new EmulatorHelper(currentProgram);

        println("PILOT A - isolated emulation, no environment provisioned");
        println("program  : " + currentProgram.getName());
        println("resolver : 0x" + Long.toHexString(MODULE_RESOLVER));
        println("");

        if (getInstructionAt(toAddr(MODULE_RESOLVER)) == null) {
            println("No instruction at resolver address.");
            println("Image base is " + currentProgram.getImageBase());
            emu.dispose();
            return;
        }

        // __cdecl frame: [ESP] = return address, [ESP+4] = first argument
        long sp = STACK;
        for (int i = NUM_STACK_ARGS; i >= 1; i--) {
            sp -= 4;
            emu.writeMemoryValue(toAddr(sp), 4, ARG_HASH);
        }
        sp -= 4;
        emu.writeMemoryValue(toAddr(sp), 4, SENTINEL);

        emu.writeRegister("ESP", sp);
        emu.writeRegister("EBP", STACK);
        emu.writeRegister(emu.getPCRegister(), MODULE_RESOLVER);

        println("instruction trace:");

        int steps = 0;
        int traced = 0;
        String err = null;
        boolean returned = false;

        while (steps < MAX_STEPS) {

            Address pc = emu.getExecutionAddress();

            if (pc.getOffset() == SENTINEL) {
                returned = true;
                break;
            }

            if (traced < TRACE_LIMIT) {
                Instruction ins = getInstructionAt(pc);
                println(String.format("  %04d  %s   %s", steps, pc,
                        ins == null ? "(unmapped)" : ins.toString()));
                traced++;
            }

            if (!emu.step(monitor)) {
                err = emu.getLastError();
                break;
            }
            steps++;
        }
        if (steps >= MAX_STEPS) {
            err = "step limit reached";
        }

        println("");
        println("steps executed : " + steps);
        println("outcome        : " + (returned ? "returned normally" : "stopped or faulted"));
        println("stopped at PC  : " + emu.getExecutionAddress());
        println("error          : " + err);
        println("");
        println("registers:");
        for (String r : new String[]{"EAX","EBX","ECX","EDX","ESI","EDI","ESP","EBP"}) {
            BigInteger v = emu.readRegister(r);
            println(String.format("  %-4s = 0x%08X", r, v.longValue()));
        }

        emu.dispose();
    }
}
