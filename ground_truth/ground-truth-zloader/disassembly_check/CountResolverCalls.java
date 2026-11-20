// Counts every call to Zloader's API resolver (FUN_030a3170) in the raw bytes,
// and how many of them Ghidra's analysis has disassembled. Read-only.
// @category Thesis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.FunctionManager;
import java.util.ArrayList;
import java.util.List;

public class CountResolverCalls extends GhidraScript {
    @Override
    public void run() throws Exception {
        final long TARGET = 0x030a3170L;
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();

        int total = 0, inFunction = 0, codeNoFunction = 0;
        List<Address> notAnalysed = new ArrayList<>();

        for (MemoryBlock blk : mem.getBlocks()) {
            if (!blk.isExecute() || !blk.isInitialized()) continue;
            long start = blk.getStart().getOffset();
            long end = blk.getEnd().getOffset();
            for (long off = start; off <= end - 4; off++) {
                Address a = toAddr(off);
                if ((mem.getByte(a) & 0xff) != 0xE8) continue;   // x86 near CALL
                int rel = mem.getInt(a.add(1));                   // 32-bit relative offset
                long dest = (off + 5 + rel) & 0xffffffffL;        // where the call lands
                if (dest != TARGET) continue;
                total++;
                boolean isCode = listing.getInstructionAt(a) != null;
                boolean inFunc = fm.getFunctionContaining(a) != null;
                if (isCode && inFunc) inFunction++;
                else if (isCode) codeNoFunction++;
                else notAnalysed.add(a);
            }
        }

        println("calls to resolver in bytes:          " + total);
        println("analysed, inside a function:         " + inFunction);
        println("analysed, but outside any function:  " + codeNoFunction);
        println("in bytes Ghidra never disassembled:  " + notAnalysed.size());
        List<Address> first = notAnalysed.subList(0, Math.min(10, notAnalysed.size()));
        println("first few not disassembled: " + first);
    }
}
