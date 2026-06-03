#include <stddef.h> // For size_t
#include <stdint.h> // For uint32_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t key = 0x9C;
    for (size_t i = 0; i < len; ++i) {
        // Cast the current byte to uint32_t to ensure it's treated as a 32-bit
        // unsigned integer, mimicking Python's 'dword = byte & 0xffffffff'.
        uint32_t dword = (uint32_t)data[i];

        // Multiply key by 3. The result is masked to 32 bits to explicitly
        // mimic Python's integer overflow behavior.
        key = (key * 3) & 0xFFFFFFFF;

        // Add the current dword to key. The result is masked to 32 bits to
        // explicitly mimic Python's integer overflow behavior.
        key = (key + dword) & 0xFFFFFFFF;
    }
    return key;
}