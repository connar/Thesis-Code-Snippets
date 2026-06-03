#include <stdint.h> // For uint32_t, uint8_t, size_t

// Helper function for Rotate Right
static uint32_t ror(uint32_t dword, int bits) {
    // Ensure the result is masked to 32 bits, mimicking Python's explicit 0xFFFFFFFF mask.
    // For uint32_t, this mask is often redundant as arithmetic naturally wraps,
    // but it's included for strict adherence to the Python behavior.
    return ((dword >> bits) | (dword << (32 - bits))) & 0xFFFFFFFF;
}

uint32_t hash(const unsigned char* data, size_t len) {
    // Find the separator b'\x00\x00\x00'
    size_t separator_idx = (size_t)-1; // Initialize to an invalid index

    // The separator b'\x00\x00\x00' requires at least 3 bytes.
    // If the data length is less than 3, it cannot contain the separator.
    if (len < 3) {
        return 0xfffffffe;
    }

    for (size_t i = 0; i <= len - 3; ++i) {
        if (data[i] == 0 && data[i+1] == 0 && data[i+2] == 0) {
            separator_idx = i;
            break;
        }
    }

    // If the separator b'\x00\x00\x00' was not found, return 0xfffffffe
    if (separator_idx == (size_t)-1) {
        return 0xfffffffe;
    }

    uint32_t module_hash = 0;
    // Hash the module part. In Python, `module += b'\x00\x00\x00'` means
    // the module hash includes the three null bytes of the separator.
    // The loop goes up to `separator_idx + 2` (inclusive), covering `separator_idx + 3` bytes.
    for (size_t i = 0; i < separator_idx + 3; ++i) {
        module_hash = ror(module_hash, 13);
        // Cast to uint32_t to avoid sign extension issues when adding byte values
        module_hash += (uint32_t)data[i];
    }

    uint32_t api_hash = 0;
    // Hash the API part, starting immediately after the three null bytes of the separator.
    // The loop starts from `separator_idx + 3`.
    for (size_t i = separator_idx + 3; i < len; ++i) {
        api_hash = ror(api_hash, 13);
        // Cast to uint32_t to avoid sign extension issues when adding byte values
        api_hash += (uint32_t)data[i];
    }

    // The final hash is the sum of module_hash and api_hash.
    // The result is masked to 32 bits, mimicking Python's explicit 0xFFFFFFFF mask.
    // For uint32_t, addition naturally wraps, so this mask is often redundant,
    // but it's included for strict adherence to the Python behavior.
    return (module_hash + api_hash) & 0xFFFFFFFF;
}