#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

// Helper for right rotation (ror) of a 32-bit unsigned integer
static uint32_t ror32(uint32_t val, unsigned int r_bits) {
    // Ensure r_bits is within the range [0, 31]
    r_bits %= 32;
    
    // If r_bits is 0, no rotation is needed, and it avoids undefined behavior
    // of shifting by 32 bits for a 32-bit type.
    if (r_bits == 0) {
        return val;
    }
    
    // Perform the right rotation
    return (val >> r_bits) | (val << (32 - r_bits));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t GENERATED_HASH = 0;

    for (size_t i = 0; i < len; ++i) {
        // segment_1 = ror(GENERATED_HASH, 13, 32) & 0xffffffff
        // The & 0xffffffff is implicit for uint32_t in C.
        uint32_t segment_1 = ror32(GENERATED_HASH, 13);
        
        // segment_2 = character
        // character is data[i], which is unsigned char.
        // It's promoted to uint32_t for arithmetic operations.
        uint32_t segment_2 = data[i];
        
        // if segment_2 >= 97: segment_2 -= 32
        // This mimics the Python logic for character transformation.
        if (segment_2 >= 97) {
            segment_2 -= 32;
        }
        
        // GENERATED_HASH = segment_1 + segment_2
        // Addition with uint32_t naturally handles 32-bit unsigned overflow.
        GENERATED_HASH = segment_1 + segment_2;
    }

    // return GENERATED_HASH + 10
    // Final addition, overflow handled by uint32_t.
    return GENERATED_HASH + 10;
}