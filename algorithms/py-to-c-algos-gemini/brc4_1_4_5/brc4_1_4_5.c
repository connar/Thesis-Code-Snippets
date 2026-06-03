#include <stddef.h> // Required for size_t
#include <stdint.h> // Required for uint32_t

// Function signature MUST be strictly: 'uint32_t hash(const unsigned char* data, size_t len)'
uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t result = 0;

    for (size_t i = 0; i < len; ++i) {
        // Python's 'int' type handles arbitrary precision.
        // To mimic this behavior where intermediate calculations might exceed 32 bits
        // before being truncated, we use a 64-bit unsigned integer for 'temp'.
        uint64_t temp = (uint64_t)2049 * result;

        // Bitwise OR with a constant. Use ULL suffix for uint64_t literal.
        temp |= 0x2800000ULL; 
        
        // Add the current character.
        // Requirement 3: Cast to (unsigned int) first to avoid sign extension.
        // (unsigned char)data[i] is promoted to (unsigned int) for the addition.
        temp += (unsigned int)data[i];
        
        // Python's 'result = temp & 0xFFFFFFFF' explicitly truncates the
        // potentially larger 'temp' value to its lower 32 bits.
        // We perform the same operation here, then cast to uint32_t for 'result'.
        result = (uint32_t)(temp & 0xFFFFFFFFULL);
    }
    
    return result;
}