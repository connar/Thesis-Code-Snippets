#include <stdint.h>
#include <stddef.h>

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t result = 0x2b;

    for (size_t i = 0; i < len; ++i) {
        result = result * 0x010F + (unsigned int)data[i];
    }

    return result & 0x1fffff;
}