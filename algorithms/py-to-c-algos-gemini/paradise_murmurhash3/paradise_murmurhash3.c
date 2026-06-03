#include <stdint.h> // For uint32_t, size_t

// fmix function (static to limit scope to this translation unit)
static uint32_t fmix(uint32_t h) {
    h ^= h >> 16;
    h = (h * 0x85ebca6bU); // Implicitly wraps due to uint32_t type
    h ^= h >> 13;
    h = (h * 0xc2b2ae35U); // Implicitly wraps due to uint32_t type
    h ^= h >> 16;
    return h;
}

// Main hash function
uint32_t hash(const unsigned char* data, size_t len) {
    const uint32_t seed = 0xDEADC0DEU;
    uint32_t h1 = seed;

    const uint32_t c1 = 0xcc9e2d51U;
    const uint32_t c2 = 0x1b873593U;

    size_t nblocks = len / 4;

    // body
    for (size_t i = 0; i < nblocks; ++i) {
        size_t block_start = i * 4;
        // Extract 4 bytes as a little-endian 32-bit integer
        uint32_t k1 = (uint32_t)data[block_start + 0] |
                      (uint32_t)data[block_start + 1] << 8 |
                      (uint32_t)data[block_start + 2] << 16 |
                      (uint32_t)data[block_start + 3] << 24;

        k1 *= c1;
        k1 = (k1 << 15) | (k1 >> (32 - 15)); // ROTL32(k1, 15)
        k1 *= c2;

        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >> (32 - 13)); // ROTL32(h1, 13)
        h1 = h1 * 5 + 0xe6546b64U; // Implicitly wraps due to uint32_t type
    }

    // tail
    uint32_t k1 = 0;
    size_t tail_index = nblocks * 4;
    size_t tail_size = len & 3; // len % 4

    if (tail_size >= 3) {
        k1 ^= (uint32_t)data[tail_index + 2] << 16;
    }
    if (tail_size >= 2) {
        k1 ^= (uint32_t)data[tail_index + 1] << 8;
    }
    if (tail_size >= 1) {
        k1 ^= (uint32_t)data[tail_index + 0];
    }

    if (tail_size > 0) {
        k1 *= c1;
        k1 = (k1 << 15) | (k1 >> (32 - 15)); // ROTL32(k1, 15)
        k1 *= c2;
        h1 ^= k1;
    }

    // finalization
    h1 ^= (uint32_t)len; // Cast len to uint32_t for XOR operation
    return fmix(h1);
}