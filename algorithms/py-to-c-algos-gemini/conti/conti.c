#include <stdint.h> // For uint32_t
#include <stddef.h> // For size_t

// The constant 0x5BD1E995
#define C1 0x5BD1E995

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t h1 = 0xFF889912; // Corresponds to Python's v15
    uint32_t k1_tail = 0;     // Corresponds to Python's hash_val for tail processing

    const unsigned char* current_data_ptr = data;
    size_t remaining_len = len;

    // Process 4-byte chunks
    size_t num_blocks = remaining_len / 4;
    while (num_blocks > 0) {
        // Read 4 bytes as a little-endian 32-bit integer
        // Python's: API_buffer[API_buffer_count + 3] << 24 | ... | API_buffer[API_buffer_count]
        uint32_t k1 = (uint32_t)current_data_ptr[0] |
                      (uint32_t)current_data_ptr[1] << 8 |
                      (uint32_t)current_data_ptr[2] << 16 |
                      (uint32_t)current_data_ptr[3] << 24;

        k1 *= C1;
        k1 ^= k1 >> 24;
        k1 *= C1;

        h1 *= C1;
        h1 ^= k1;

        current_data_ptr += 4;
        remaining_len -= 4;
        num_blocks--;
    }

    // Process remaining bytes (tail)
    // Corresponds to Python's if/elif chain for hash_val
    switch (remaining_len) {
        case 3:
            k1_tail ^= (uint32_t)current_data_ptr[2] << 16;
            // Fallthrough
        case 2:
            k1_tail ^= (uint32_t)current_data_ptr[1] << 8;
            // Fallthrough
        case 1:
            k1_tail ^= (uint32_t)current_data_ptr[0];
            // No default case for 0, as k1_tail remains 0.
    }

    // Finalization
    // Mix k1_tail into h1
    k1_tail *= C1;
    k1_tail ^= k1_tail >> 24;
    k1_tail *= C1;

    h1 *= C1;
    h1 ^= k1_tail;

    // Mix len into h1
    uint32_t len_val = (uint32_t)len; // Cast len to uint32_t for arithmetic
    len_val *= C1;
    len_val ^= len_val >> 24;
    len_val *= C1;

    h1 *= C1;
    h1 ^= len_val;

    // Final avalanche
    h1 ^= h1 >> 13;
    h1 *= C1;
    h1 ^= h1 >> 15;

    return h1;
}