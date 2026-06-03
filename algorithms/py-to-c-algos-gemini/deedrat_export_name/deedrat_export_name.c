#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    size_t i = 0; // Mimics Python's 1-based loop counter
    uint32_t ecx = 0;
    uint32_t eax = 0;
    uint32_t edi = 0;
    uint32_t esi = 0;

    for (size_t k = 0; k < len; ++k) {
        unsigned char c = data[k];
        i = i + 1; // Increment 1-based counter

        // Cast c to uint32_t to ensure zero-extension when assigned to edi
        edi = (uint32_t)c;

        ecx = esi;
        eax = esi;

        if (i & 1) { // Equivalent to i % 2 != 0 or i & 1 != 0
            // Python: ecx = (ecx << 0x5) & 0xffffffff
            // For uint32_t, left shift naturally wraps around at 32 bits.
            ecx = ecx << 5;
            
            // Python: eax = (eax >> 0x1) & 0xffffffff
            // For uint32_t, right shift naturally wraps around at 32 bits.
            eax = eax >> 1;
            
            ecx = ecx ^ eax;
            ecx = ecx ^ edi;
        } else {
            // Python: ecx = (ecx << 0x9) & 0xffffffff
            ecx = ecx << 9;
            
            // Python: eax = (eax >> 0x3) & 0xffffffff
            eax = eax >> 3;
            
            ecx = ecx ^ eax;
            ecx = ecx ^ edi;
            
            // Python: ecx = ~(ecx) & 0xffffffff
            // For uint32_t, bitwise NOT (~ecx) already produces a 32-bit result.
            ecx = ~ecx;
        }
        esi = esi ^ ecx;
    }
    // Python: return esi & 0x7fffffff
    // Mask the final result to 31 bits (positive signed int range).
    return esi & 0x7fffffff;
}