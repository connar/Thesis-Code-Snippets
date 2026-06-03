#include <stdint.h> // For uint32_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0x811c9dc5U; // Initial FNV offset basis

    for (size_t i = 0; i < len; ++i) {
        // FNV prime multiplication, XOR with current byte, and mask to 32-bit.
        // 0x1000193U is the FNV prime (16777619).
        // (uint32_t)data[i] ensures the byte is promoted to uint32_t before XOR,
        // avoiding any potential sign extension issues.
        // The & 0xFFFFFFFFU explicitly ensures the result remains within 32 bits,
        // mimicking Python's behavior and satisfying the requirement.
        val = ((val * 0x1000193U) ^ (uint32_t)data[i]) & 0xFFFFFFFFU;
    }

    return val;
}