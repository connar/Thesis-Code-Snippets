#include <stdint.h>
#include <stddef.h>

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t result = 0x4e67c6a7;
    const unsigned char* current_data = data;
    size_t current_len = len;

    // Handle prefix "Nt" or "Zw"
    if (len >= 2) {
        if ((data[0] == 'N' && data[1] == 't') || (data[0] == 'Z' && data[1] == 'w')) {
            current_data += 2;
            current_len -= 2;
        }
    }

    for (size_t i = 0; i < current_len; ++i) {
        // Cast the byte to uint32_t to prevent sign extension during arithmetic operations.
        uint32_t byte_val = (uint32_t)current_data[i];
        
        // Calculate the term: (byte_val + (result >> 2) + (result << 5))
        // All operands are uint32_t, so additions will naturally wrap around 2^32,
        // mimicking Python's `& 0xffffffff` behavior for the intermediate sum.
        uint32_t term = byte_val + (result >> 2) + (result << 5);
        
        result ^= term;
    }

    return result;
}