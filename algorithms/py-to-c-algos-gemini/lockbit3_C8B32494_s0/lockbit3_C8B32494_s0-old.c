#include <stdint.h>
#include <string.h>

// Performs a 32-bit right rotation.
static uint32_t ror(uint32_t n, unsigned int rotations) {
    return (n >> rotations) | (n << (32 - rotations));
}

// Implements the core hashing logic for a byte string.
// It mimics Python's behavior of appending a null byte and breaking if a null byte is encountered.
static uint32_t hash_algo_internal(const unsigned char* s, size_t s_len, uint32_t seed) {
    uint32_t result = 0xC8B32494 ^ seed;
    size_t i;

    for (i = 0; i < s_len; ++i) {
        uint8_t c = s[i];
        result = ror(result, 0x0d);
        result = (result + (uint32_t)c); // Cast to uint32_t for addition to prevent sign extension
        if (c == 0x00) {
            // If an embedded null byte is found, process it and stop,
            // as per Python's 'if c == 0x00: break' after processing 'c'.
            return result;
        }
    }
    // If the loop finishes without finding a null byte,
    // it means the original string did not contain one.
    // In this case, the Python code implicitly appends one and processes it.
    result = ror(result, 0x0d);
    result = (result + (uint32_t)0x00); // Process the implicitly appended null byte

    return result;
}

// Main hashing function as per the specified signature.
uint32_t hash(const unsigned char* data, size_t len) {
    const unsigned char* dll_marker = (const unsigned char*)".dll";
    size_t dll_marker_len = 4; // Length of ".dll"

    const unsigned char* p_dll = NULL;
    // Search for the first occurrence of ".dll"
    if (len >= dll_marker_len) {
        for (size_t i = 0; i <= len - dll_marker_len; ++i) {
            if (memcmp(data + i, dll_marker, dll_marker_len) == 0) {
                p_dll = data + i;
                break;
            }
        }
    }

    if (p_dll == NULL) {
        // If ".dll" is not found, return 0xfffffffe (mimics Python's len(split) != 2 case)
        return 0xfffffffe;
    }

    // Check for a second occurrence of ".dll"
    const unsigned char* p_dll_second = NULL;
    size_t offset_after_first_dll = (p_dll - data) + dll_marker_len;
    if (len >= offset_after_first_dll + dll_marker_len) {
        for (size_t i = offset_after_first_dll; i <= len - dll_marker_len; ++i) {
            if (memcmp(data + i, dll_marker, dll_marker_len) == 0) {
                p_dll_second = data + i;
                break;
            }
        }
    }

    if (p_dll_second != NULL) {
        // If more than one ".dll" is found, return 0xfffffffe
        return 0xfffffffe;
    }

    // Exactly one ".dll" found, proceed with splitting
    // dll_name includes the ".dll" part
    size_t dll_name_len = (p_dll - data) + dll_marker_len;
    // api_name is the part after ".dll"
    const unsigned char* api_name_ptr = p_dll + dll_marker_len;
    size_t api_name_len = len - dll_name_len;

    uint32_t seed = 0;
    uint32_t dll_hash = hash_algo_internal(data, dll_name_len, seed);
    uint32_t tmp_hash = hash_algo_internal(api_name_ptr, api_name_len, dll_hash);

    // Perform bitwise NOT and mask to ensure 32-bit result
    return ~tmp_hash & 0xffffffff;
}