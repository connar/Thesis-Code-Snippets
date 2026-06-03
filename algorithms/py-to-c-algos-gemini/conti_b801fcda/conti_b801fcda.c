#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    // The Python code's API_buffer creation and subsequent ord(chr()) loop
    // effectively create a byte-for-byte copy of the input 'data'
    // and then perform a no-op conversion.
    // In C, we can directly use the input 'data' pointer.

    uint32_t hash_val = 0;
    uint32_t v15 = 0xB801FCDA; // Seed value

    size_t current_data_idx = 0; // Corresponds to API_buffer_count
    size_t remaining_len = len;  // Corresponds to string_length_2

    // Process data in 4-byte chunks
    if (len >= 4) {
        size_t num_chunks = remaining_len >> 2; // Number of 4-byte chunks
        remaining_len &= 3;                     // Remaining bytes (0, 1, 2, or 3)

        while (num_chunks > 0) {
            // Read 4 bytes in little-endian order
            uint32_t temp_buffer_val = (uint32_t)data[current_data_idx] |
                                       (uint32_t)data[current_data_idx + 1] << 8 |
                                       (uint32_t)data[current_data_idx + 2] << 16 |
                                       (uint32_t)data[current_data_idx + 3] << 24;

            uint32_t temp = 0x5BD1E995 * temp_buffer_val; // Multiplications wrap at 32-bit
            current_data_idx += 4;
            v15 = (0x5BD1E995 * (temp ^ (temp >> 24))) ^ (0x5BD1E995 * v15);
            num_chunks--;
        }
    }

    // Process remaining bytes (0, 1, 2, or 3)
    // This section corresponds to Python's v18, v19 logic
    switch (remaining_len) {
        case 3:
            hash_val ^= (uint32_t)data[current_data_idx + 2] << 16;
            // Fallthrough
        case 2:
            hash_val ^= (uint32_t)data[current_data_idx + 1] << 8;
            // Fallthrough
        case 1:
            hash_val ^= (uint32_t)data[current_data_idx];
            break;
        // case 0: hash_val remains 0 for this part, no action needed
    }

    // Finalization steps
    uint32_t v20 = 0x5BD1E995 * hash_val;
    uint32_t edi = 0x5BD1E995 * (uint32_t)len; // Cast len to uint32_t for multiplication

    uint32_t eax = v20 >> 24;
    eax ^= v20;

    uint32_t ecx = 0x5BD1E995 * eax;
    eax = 0x5BD1E995 * v15;

    ecx ^= eax;

    eax = edi;
    eax >>= 24;
    eax ^= edi;

    uint32_t edx = 0x5BD1E995 * ecx;
    eax = 0x5BD1E995 * eax;
    edx ^= eax;
    eax = edx;

    eax >>= 13;
    eax ^= edx;

    ecx = 0x5BD1E995 * eax;
    eax = ecx;
    eax >>= 15;
    eax ^= ecx;

    return eax;
}