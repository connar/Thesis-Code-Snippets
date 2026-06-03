#include <stdint.h>
#include <stddef.h>

uint32_t hash(const unsigned char* data, size_t len) {
    // [FIX] Optimization/Collision Filter:
    // Only process functions that start with V, C, or W (VirtualAlloc, CreateThread, WaitFor...)
    // This allows us to skip ntdll.dll exports (which start with Nt/Zw) that might cause collisions.
    uint8_t first = data[0];
    if (first != 'V' && first != 'C' && first != 'W') {
        return 0; // Return 0 to ensure it doesn't match our target hash
    }

    uint32_t result = 0x4e67c6a7;
    
    // Note: I removed the "Nt/Zw" stripping logic because we are explicitly 
    // targeting Kernel32 functions, so we don't want to modify the string.

    for (size_t i = 0; i < len; ++i) {
        uint32_t byte_val = (uint32_t)data[i];
        
        // (byte_val + (result >> 2) + (result << 5))
        uint32_t term = byte_val + (result >> 2) + (result << 5);
        
        result ^= term;
    }

    return result;
}