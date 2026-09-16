// Pilot C: map a real DLL image from disk and resolve an API hash taken from
// the sample's own call sites.
//
// Maps the PE headers and the export data region of ntdll.dll at a synthesised
// base address, then runs the sample's API resolver against hash 0x183679F2.
// The expected answer is computed independently by parsing the export table
// directly, so the result is self-verifying.
//
// No candidate list is supplied. Candidate names come from the mapped library's
// own AddressOfNames array.
//
// Sample: Netwalker, SHA-256 58e923ff158fb5aecd293b7a0e0d305296110b83c6e270786edcc4fea1c8404c
// Requires: C:\dll_corpus\x86\ntdll.dll  (copy from C:\Windows\SysWOW64)
//
//@category Thesis
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.*;
import java.nio.file.*;

public class PilotC extends GhidraScript {

    // FUN_00401000(moduleBase, apiHash): resolve an export by hash
    private static final long API_RESOLVER = 0x00401000L;

    // Ground truth from independent reverse engineering of this sample
    private static final long   TARGET_HASH = 0x183679F2L;
    private static final String EXPECT_API  = "LdrLoadDll";

    private static final String DLL_PATH = "C:\\dll_corpus\\x86\\ntdll.dll";
    private static final long   DLLBASE  = 0x77000000L;

    private static final long STACK     = 0x00300000L;
    private static final long SENTINEL  = 0x00BADBADL;
    private static final int  MAX_STEPS = 2000000;

    private int bytesMapped = 0;

    public void run() throws Exception {

        println("PILOT C - real DLL export table mapped from disk");
        println("program : " + currentProgram.getName());
        println("dll     : " + DLL_PATH);
        println("");

        byte[] file;
        try {
            file = Files.readAllBytes(Paths.get(DLL_PATH));
        } catch (Exception e) {
            println("Cannot read " + DLL_PATH + ": " + e.getMessage());
            return;
        }
        println("file size on disk : " + file.length + " bytes");

        // ---- parse PE headers ----

        int elfanew = rd32(file, 0x3C);
        int optHdr  = elfanew + 4 + 20;

        if (rd16(file, optHdr) != 0x10B) {
            println("Not a 32-bit PE. Use the SysWOW64 copy for a 32-bit sample.");
            return;
        }

        int sizeOfHeaders = rd32(file, optHdr + 0x54);
        int exportRva     = rd32(file, optHdr + 0x60);
        int exportSize    = rd32(file, optHdr + 0x64);
        int numSections   = rd16(file, elfanew + 6);
        int sizeOfOptHdr  = rd16(file, elfanew + 20);
        int sectionTable  = elfanew + 4 + 20 + sizeOfOptHdr;

        println("export dir RVA    : 0x" + Integer.toHexString(exportRva)
                + ", size " + exportSize);

        // ---- map headers and the export data region only ----

        EmulatorHelper emu = new EmulatorHelper(currentProgram);

        writeBytes(emu, DLLBASE, slice(file, 0, sizeOfHeaders));

        int expOff = rvaToOff(file, exportRva, sectionTable, numSections);
        int expLen = Math.min(exportSize, file.length - expOff);
        writeBytes(emu, DLLBASE + exportRva, slice(file, expOff, expLen));

        println("mapped            : " + bytesMapped + " bytes ("
                + String.format("%.1f", 100.0 * bytesMapped / file.length)
                + "% of the file)");

        // ---- compute the expected answer independently ----

        int expDirOff = rvaToOff(file, exportRva, sectionTable, numSections);
        int numNames  = rd32(file, expDirOff + 0x18);
        int namesOff  = rvaToOff(file, rd32(file, expDirOff + 0x20), sectionTable, numSections);
        int funcsOff  = rvaToOff(file, rd32(file, expDirOff + 0x1C), sectionTable, numSections);
        int ordsOff   = rvaToOff(file, rd32(file, expDirOff + 0x24), sectionTable, numSections);

        long expectedAddr = 0;
        for (int i = 0; i < numNames; i++) {
            int nameOff = rvaToOff(file, rd32(file, namesOff + i * 4), sectionTable, numSections);
            StringBuilder s = new StringBuilder();
            for (int k = nameOff; k < file.length && file[k] != 0; k++) {
                s.append((char) file[k]);
            }
            if (s.toString().equals(EXPECT_API)) {
                int ord  = rd16(file, ordsOff + i * 2);
                int fRva = rd32(file, funcsOff + ord * 4);
                expectedAddr = DLLBASE + (fRva & 0xFFFFFFFFL);
                break;
            }
        }
        println("exports in DLL    : " + numNames);
        println("expected " + EXPECT_API + " at 0x" + String.format("%08X", expectedAddr));

        // ---- run the resolver ----

        long sp = STACK;
        sp -= 4; emu.writeMemoryValue(toAddr(sp), 4, TARGET_HASH);
        sp -= 4; emu.writeMemoryValue(toAddr(sp), 4, DLLBASE);
        sp -= 4; emu.writeMemoryValue(toAddr(sp), 4, SENTINEL);
        emu.writeRegister("ESP", sp);
        emu.writeRegister("EBP", STACK);
        emu.writeRegister(emu.getPCRegister(), API_RESOLVER);

        println("");
        println("resolving hash 0x" + String.format("%08X", TARGET_HASH));

        int steps = 0;
        String err = null;
        boolean returned = false;

        while (steps < MAX_STEPS) {
            if (emu.getExecutionAddress().getOffset() == SENTINEL) {
                returned = true;
                break;
            }
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
        println("outcome        : " + (returned ? "returned normally" : "stopped or faulted"));
        println("error          : " + err);
        println("returned       : 0x" + String.format("%08X", eax));
        println("expected       : 0x" + String.format("%08X", expectedAddr));
        println("bytes mapped   : " + bytesMapped);
        println("");
        println(returned && eax == expectedAddr && eax != 0
                ? "MATCH - correct API address returned"
                : "NO MATCH");

        emu.dispose();
    }

    private int rd16(byte[] b, int o) {
        return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8);
    }

    private int rd32(byte[] b, int o) {
        return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8)
             | ((b[o + 2] & 0xFF) << 16) | ((b[o + 3] & 0xFF) << 24);
    }

    private byte[] slice(byte[] src, int off, int len) {
        if (off + len > src.length) len = src.length - off;
        byte[] out = new byte[len];
        System.arraycopy(src, off, out, 0, len);
        return out;
    }

    private void writeBytes(EmulatorHelper e, long addr, byte[] data) throws Exception {
        final int CHUNK = 4096;
        for (int i = 0; i < data.length; i += CHUNK) {
            int n = Math.min(CHUNK, data.length - i);
            byte[] part = new byte[n];
            System.arraycopy(data, i, part, 0, n);
            e.writeMemory(toAddr(addr + i), part);
        }
        bytesMapped += data.length;
    }

    // Translate a relative virtual address to a file offset using the section table.
    private int rvaToOff(byte[] f, int rva, int sectionTable, int numSections) {
        for (int i = 0; i < numSections; i++) {
            int sh  = sectionTable + i * 40;
            int va  = rd32(f, sh + 12);
            int vs  = rd32(f, sh + 8);
            int raw = rd32(f, sh + 16);
            int ptr = rd32(f, sh + 20);
            if (rva >= va && rva < va + Math.max(vs, raw)) {
                return rva - va + ptr;
            }
        }
        return rva;  // inside the headers
    }
}
