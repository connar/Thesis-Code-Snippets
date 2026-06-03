#include <stdint.h> // For uint32_t, uint8_t
#include <string.h> // For strlen (though len is provided), memcpy
#include <stdlib.h> // For malloc, free
#include <ctype.h>  // For tolower

// Helper function fmix
static uint32_t fmix(uint32_t h) {
    h ^= h >> 16;
    h  = (h * 0x85ebca6b); // uint32_t multiplication wraps naturally
    h ^= h >> 13;
    h  = (h * 0xc2b2ae35); // uint32_t multiplication wraps naturally
    h ^= h >> 16;
    return h;
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t seed = 0xe9ff0077;

    // The Python code converts the input key to lowercase bytes.
    // We need to mimic this by creating a temporary buffer and lowercasing the input.
    unsigned char* temp_key = (unsigned char*)malloc(len);
    if (temp_key == NULL) {
        // Handle allocation error. For hashing, often a critical error,
        // but returning 0 is a valid uint32_t.
        return 0; 
    }

    for (size_t i = 0; i < len; ++i) {
        temp_key[i] = (unsigned char)tolower((unsigned char)data[i]);
    }

    size_t length = len;
    size_t nblocks = length / 4;

    uint32_t h1 = seed;

    uint32_t c1 = 0xcc9e2d51;
    uint32_t c2 = 0x1b873593;

    // Body
    const uint8_t* blocks = (const uint8_t*)temp_key; // Treat temp_key as uint8_t array
    for (size_t i = 0; i < nblocks; ++i) {
        // Python code reads bytes in little-endian order for k1
        uint32_t k1 = ((uint32_t)blocks[i * 4 + 0]) |
                      ((uint32_t)blocks[i * 4 + 1] << 8) |
                      ((uint32_t)blocks[i * 4 + 2] << 16) |
                      ((uint32_t)blocks[i * 4 + 3] << 24);
             
        k1 *= c1; // uint32_t multiplication wraps naturally
        k1 = (k1 << 15) | (k1 >> 17); // ROTL32
        k1 *= c2; // uint32_t multiplication wraps naturally
        
        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >> 19); // ROTL32
        h1 = h1 * 5 + 0xe6546b64; // uint32_t arithmetic wraps naturally
    }

    // Tail
    const uint8_t* tail = (const uint8_t*)(temp_key + nblocks * 4);
    uint32_t k1 = 0;
    size_t tail_size = length & 3; // length % 4

    switch (tail_size) {
        case 3: k1 ^= (uint32_t)tail[2] << 16; // Fallthrough
        case 2: k1 ^= (uint32_t)tail[1] << 8;  // Fallthrough
        case 1: k1 ^= (uint32_t)tail[0];
                // The following operations apply if tail_size is 1, 2, or 3
                k1 *= c1;
                k1 = (k1 << 15) | (k1 >> 17); // ROTL32
                k1 *= c2;
                h1 ^= k1;
                break; // Break after processing k1 and h1 for tail_size > 0
        case 0:
        default: // No tail bytes
            break;
    }

    // Finalization
    uint32_t unsigned_val = fmix(h1 ^ (uint32_t)length);

    // Free the temporary buffer
    free(temp_key);

    return unsigned_val;
}