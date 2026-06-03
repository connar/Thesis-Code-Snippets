#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

// Forward declaration for the finalize function
static uint32_t murmur_hash_finalize(uint32_t hash_value);

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t length = (uint32_t)len;
    uint32_t hash_val = 0x4CDC03;
    
    const uint32_t c1 = 0xCC9E2D51;
    const uint32_t c2 = 0x1B873593;
    
    const uint8_t* current_data = (const uint8_t*)data;
    
    uint32_t num_chunks = length / 4;
    
    for (uint32_t i = 0; i < num_chunks; ++i) {
        uint32_t chunk = 0;
        // Load 4 bytes as a little-endian 32-bit integer
        // Cast to uint32_t before shifting to prevent potential sign extension issues
        // if uint8_t were promoted to a signed int type before the shift.
        chunk = (uint32_t)current_data[0] |
                ((uint32_t)current_data[1] << 8) |
                ((uint32_t)current_data[2] << 16) |
                ((uint32_t)current_data[3] << 24);
        
        current_data += 4; // Advance pointer to the next chunk
        
        chunk *= c1;
        chunk = (chunk << 15) | (chunk >> 17); // Equivalent to ROTL32(chunk, 15)
        chunk *= c2;
        
        hash_val ^= chunk;
        hash_val = (hash_val << 13) | (hash_val >> 19); // Equivalent to ROTL32(hash_val, 13)
        // uint32_t arithmetic naturally handles the 0xFFFFFFFF mask for multiplication and subtraction
        hash_val = (hash_val * 5) - 0x19AB949C;
    }
    
    uint32_t remaining = length & 3; // length % 4
    if (remaining > 0) {
        uint32_t tail = 0;
        
        // Load remaining bytes as a little-endian integer
        switch (remaining) {
            case 3:
                tail ^= (uint32_t)current_data[2] << 16;
                // Fallthrough
            case 2:
                tail ^= (uint32_t)current_data[1] << 8;
                // Fallthrough
            case 1:
                tail ^= (uint32_t)current_data[0];
                break;
        }
        
        tail *= c1;
        tail = (tail << 15) | (tail >> 17); // Equivalent to ROTL32(tail, 15)
        tail *= c2;
        
        hash_val ^= tail;
    }
    
    hash_val ^= length;
    return murmur_hash_finalize(hash_val);
}

static uint32_t murmur_hash_finalize(uint32_t hash_value) {
    hash_value ^= hash_value >> 16;
    hash_value *= 0x85EBCA6B;
    hash_value ^= hash_value >> 13;
    hash_value *= 0xC2B2AE35;
    hash_value ^= hash_value >> 16;
    return hash_value;
}