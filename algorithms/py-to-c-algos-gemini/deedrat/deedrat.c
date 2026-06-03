#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    size_t i = 0;
    uint32_t ecx = 0;
    uint32_t eax = 0;
    uint32_t edi = 0;
    uint32_t esi = 0;

    for (i = 0; i < len; ++i) {
        uint8_t c_byte = data[i];
        
        // Character transformation
        // Python: if c < 0x61: edi = c+0x20 else: edi = c
        // Requirement 3: When XORing/Adding bytes, cast to (unsigned int) first to avoid sign extension.
        // uint8_t c_byte is promoted to int for comparison.
        // For addition, c_byte is cast to uint32_t (an unsigned int type) before adding 0x20.
        if (c_byte < 0x61) {
            edi = (uint32_t)c_byte + 0x20;
        } else {
            edi = (uint32_t)c_byte;
        }
        
        ecx = esi;
        eax = esi;

        // Python's 'i' is 1-indexed in the loop (i = i+1).
        // In C, 'i' is 0-indexed. So, for the first character (C's i=0), Python's 'i' is 1 (odd).
        // For the second character (C's i=1), Python's 'i' is 2 (even).
        // The condition `(i + 1) & 1` correctly mimics Python's `i & 1 != 0`.
        if ((i + 1) & 1) { // Python's 'i' is odd
            ecx = (ecx << 0x5) & 0xffffffff;
            eax = (eax >> 0x1) & 0xffffffff;
            ecx = (ecx ^ eax) & 0xffffffff;
            ecx = (ecx ^ edi) & 0xffffffff;
        } else { // Python's 'i' is even
            ecx = (ecx << 0x9) & 0xffffffff;
            eax = (eax >> 0x3) & 0xffffffff;
            ecx = (ecx ^ eax) & 0xffffffff;
            ecx = (ecx ^ edi) & 0xffffffff;
            ecx = (~ecx) & 0xffffffff;
        }
        esi = esi ^ ecx; // Python: esi = esi ^ ecx (no explicit mask here)
    }
    return esi;
}