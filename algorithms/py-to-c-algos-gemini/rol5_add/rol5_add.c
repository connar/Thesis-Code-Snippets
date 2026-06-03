#include <stdint.h> // For uint32_t
#include <stddef.h> // For size_t

// Helper function for rotate left (ROL) for 32-bit unsigned integers
static uint32_t rol(uint32_t inVal, unsigned int numShifts) {
    // For uint32_t, operations naturally wrap around at 2^32,
    // effectively mimicking the 0xffffffff bitmask from the Python code.
    return (inVal << numShifts) | (inVal >> (32 - numShifts));
}

// Main hashing function
uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;
    size_t i;

    for (i = 0; i < len; ++i) {
        val = rol(val, 0x5); // Rotate left by 5 bits
        // Add the current byte. Cast to unsigned int to prevent sign extension
        // before addition, as per requirement 3.
        val += (unsigned int)data[i];
    }

    // Requirement 5: Integer overflow mimics Python behavior (mask with 0xFFFFFFFF).
    // Since 'val' is uint32_t, its operations already wrap around at 2^32,
    // naturally handling the 0xFFFFFFFF masking.
    return val;
}