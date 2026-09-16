// Pilot B: provision a minimal process environment and resolve a module by hash.
//
// Stage 1 computes the target hash by emulating the sample's own hash function
// on a module name. Stage 2 provisions a PEB, loader data, and a two-entry
// module list, then runs the module resolver against that hash.
//
// Sample: Netwalker, SHA-256 58e923ff158fb5aecd293b7a0e0d305296110b83c6e270786edcc4fea1c8404c
//
//@category Thesis
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.*;
import java.math.BigInteger;

public class PilotB extends GhidraScript {

    // Sample functions
    private static final long MODULE_RESOLVER = 0x00401220L;  // resolve module handle by hash
    private static final long NT_CURRENT_PEB  = 0x00413C70L;  // returns FS:[0x30]
    private static final long HASH_FUNC       = 0x00407990L;  // hash(wstr, charCount, wideFlag)

    // Synthesised process structures
    private static final long PEB_BASE = 0x7EFDE000L;
    private static final long LDR_BASE = 0x7EFDE200L;
    private static final long ENTRY1   = 0x7EFDE300L;  // points at InMemoryOrderLinks
    private static final long ENTRY2   = 0x7EFDE400L;
    private static final long NAME1    = 0x7EFDE500L;
    private static final long NAME2    = 0x7EFDE560L;
    private static final long DLLBASE1 = 0x71000000L;
    private static final long DLLBASE2 = 0x77000000L;

    private static final long STACK     = 0x00300000L;
    private static final long SENTINEL  = 0x00BADBADL;
    private static final int  MAX_STEPS = 500000;

    private static final String MOD1 = "kernel32.dll";
    private static final String MOD2 = "ntdll.dll";

    private int bytesProvisioned = 0;

    public void run() throws Exception {

        println("PILOT B - provisioned process environment");
        println("program : " + currentProgram.getName());
        println("");

        // ---- Stage 1: hash a module name using the sample's own hash function ----

        println("stage 1: hash \"" + MOD1 + "\"");

        EmulatorHelper e1 = new EmulatorHelper(currentProgram);
        writeWide(e1, NAME1, MOD1);

        long sp = STACK;
        sp -= 4; e1.writeMemoryValue(toAddr(sp), 4, 1);              // wide flag
        sp -= 4; e1.writeMemoryValue(toAddr(sp), 4, MOD1.length());  // character count
        sp -= 4; e1.writeMemoryValue(toAddr(sp), 4, NAME1);          // string pointer
        sp -= 4; e1.writeMemoryValue(toAddr(sp), 4, SENTINEL);       // return address

        e1.writeRegister("ESP", sp);
        e1.writeRegister("EBP", STACK);
        e1.writeRegister(e1.getPCRegister(), HASH_FUNC);

        String err1 = runToSentinel(e1, MAX_STEPS);
        if (err1 != null) {
            println("  failed: " + err1);
            e1.dispose();
            return;
        }
        long modHash = e1.readRegister("EAX").longValue() & 0xFFFFFFFFL;
        println("  hash = 0x" + String.format("%08X", modHash));
        e1.dispose();

        // ---- Stage 2: provision the environment and resolve ----

        println("");
        println("stage 2: provision environment, run module resolver");

        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        bytesProvisioned = 0;

        // PEB: only PEB->Ldr at +0x0c is read
        write4(emu, PEB_BASE + 0x0C, LDR_BASE);

        // PEB_LDR_DATA: InMemoryOrderModuleList head at +0x14
        long head = LDR_BASE + 0x14;
        write4(emu, head + 0x00, ENTRY1);
        write4(emu, head + 0x04, ENTRY2);

        // Entry offsets are relative to the InMemoryOrderLinks field:
        //   +0x00 Flink   +0x04 Blink   +0x10 DllBase
        //   +0x24 BaseDllName.Length   +0x28 BaseDllName.Buffer
        write4(emu, ENTRY1 + 0x00, ENTRY2);
        write4(emu, ENTRY1 + 0x04, head);
        write4(emu, ENTRY1 + 0x10, DLLBASE1);
        write2(emu, ENTRY1 + 0x24, MOD1.length() * 2);
        write2(emu, ENTRY1 + 0x26, MOD1.length() * 2 + 2);
        write4(emu, ENTRY1 + 0x28, NAME1);

        write4(emu, ENTRY2 + 0x00, head);   // closes the circular list
        write4(emu, ENTRY2 + 0x04, ENTRY1);
        write4(emu, ENTRY2 + 0x10, DLLBASE2);
        write2(emu, ENTRY2 + 0x24, MOD2.length() * 2);
        write2(emu, ENTRY2 + 0x26, MOD2.length() * 2 + 2);
        write4(emu, ENTRY2 + 0x28, NAME2);

        writeWide(emu, NAME1, MOD1);
        writeWide(emu, NAME2, MOD2);

        println("  provisioned " + bytesProvisioned + " bytes");

        long sp2 = STACK;
        sp2 -= 4; emu.writeMemoryValue(toAddr(sp2), 4, modHash);
        sp2 -= 4; emu.writeMemoryValue(toAddr(sp2), 4, SENTINEL);
        emu.writeRegister("ESP", sp2);
        emu.writeRegister("EBP", STACK);
        emu.writeRegister(emu.getPCRegister(), MODULE_RESOLVER);

        int steps = 0;
        int pebHooks = 0;
        int hashCalls = 0;
        String err = null;
        boolean returned = false;

        while (steps < MAX_STEPS) {
            long off = emu.getExecutionAddress().getOffset();

            if (off == SENTINEL) {
                returned = true;
                break;
            }

            // The resolver obtains its PEB pointer through a helper that reads
            // FS:[0x30]. The emulator has no segment base, so the call is
            // intercepted and answered with the synthesised PEB address.
            if (off == NT_CURRENT_PEB) {
                long esp = emu.readRegister("ESP").longValue();
                long ret = read4(emu, esp);
                emu.writeRegister("ESP", esp + 4);
                emu.writeRegister("EAX", PEB_BASE);
                emu.writeRegister(emu.getPCRegister(), ret);
                pebHooks++;
                continue;
            }

            if (off == HASH_FUNC) hashCalls++;

            if (!emu.step(monitor)) {
                err = emu.getLastError();
                break;
            }
            steps++;
        }
        if (steps >= MAX_STEPS) err = "step limit reached";

        long eax = emu.readRegister("EAX").longValue() & 0xFFFFFFFFL;

        println("");
        println("steps executed : " + steps);
        println("PEB hooks      : " + pebHooks);
        println("hash calls     : " + hashCalls);
        println("outcome        : " + (returned ? "returned normally" : "stopped or faulted"));
        println("error          : " + err);
        println("returned       : 0x" + String.format("%08X", eax));
        println("expected       : 0x" + String.format("%08X", DLLBASE1));
        println("");
        println(eax == DLLBASE1 && returned
                ? "MATCH - correct module base returned"
                : "NO MATCH");

        emu.dispose();
    }

    private long read4(EmulatorHelper e, long addr) throws Exception {
        byte[] b = e.readMemory(toAddr(addr), 4);
        return ((long)(b[0] & 0xFF))
             | ((long)(b[1] & 0xFF) << 8)
             | ((long)(b[2] & 0xFF) << 16)
             | ((long)(b[3] & 0xFF) << 24);
    }

    private void write4(EmulatorHelper e, long addr, long val) throws Exception {
        e.writeMemoryValue(toAddr(addr), 4, val);
        bytesProvisioned += 4;
    }

    private void write2(EmulatorHelper e, long addr, long val) throws Exception {
        e.writeMemoryValue(toAddr(addr), 2, val);
        bytesProvisioned += 2;
    }

    private void writeWide(EmulatorHelper e, long addr, String s) throws Exception {
        byte[] b = new byte[s.length() * 2 + 2];
        for (int i = 0; i < s.length(); i++) {
            b[i * 2]     = (byte) (s.charAt(i) & 0xFF);
            b[i * 2 + 1] = (byte) ((s.charAt(i) >> 8) & 0xFF);
        }
        e.writeMemory(toAddr(addr), b);
        bytesProvisioned += b.length;
    }

    private String runToSentinel(EmulatorHelper e, int max) throws Exception {
        int n = 0;
        while (n < max) {
            if (e.getExecutionAddress().getOffset() == SENTINEL) return null;
            if (!e.step(monitor)) return e.getLastError();
            n++;
        }
        return "step limit reached";
    }
}
