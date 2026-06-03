#include <stdint.h>
#include <string.h>

// Performs a 32-bit right rotation.
static uint32_t ror(uint32_t n, unsigned int rotations) {
    return (n >> rotations) | (n << (32 - rotations));
}

// Implements the core hashing logic for a byte string.
static uint32_t hash_algo_internal(const unsigned char* s, size_t s_len, uint32_t seed) {
    uint32_t result = 0xC8B32494 ^ seed;
    size_t i;

    for (i = 0; i < s_len; ++i) {
        uint8_t c = s[i];
        result = ror(result, 0x0d);
        result = (result + (uint32_t)c);
        if (c == 0x00) return result;
    }
    // Implicit null byte processing if not found in loop
    result = ror(result, 0x0d);
    result = (result + (uint32_t)0x00); 

    return result;
}

// Main hashing function
// ADAPTED: Hardcodes 'kernel32.dll' context to match Python logic
uint32_t hash(const unsigned char* data, size_t len) {
    // 1. Define the DLL context
    // Python logic: splits "kernel32.dllVirtualAlloc" -> hashes "kernel32.dll" first.
    unsigned char dll_str[] = "kernel32.dll";
    size_t dll_len = 12; // strlen("kernel32.dll")
    
    // 2. Hash the DLL part (Seed = 0)
    uint32_t dll_hash = hash_algo_internal(dll_str, dll_len, 0);
    
    // 3. Hash the API part (Input data) using the DLL hash as the seed
    uint32_t final_hash = hash_algo_internal(data, len, dll_hash);

    // 4. Final Bitwise NOT
    return ~final_hash & 0xffffffff;
}