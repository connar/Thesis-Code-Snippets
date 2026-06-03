#include <stddef.h>
#include <stdint.h>

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t hash_value = 0;
    for (size_t i = 0; i < len; ++i) {
        hash_value = ((uint32_t)data[i] + hash_value * 0x1003f) & 0xFFFFFFFF;
    }
    return hash_value ^ 0x19ad760U;
}