#include <stdint.h> // For uint32_t, size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t h = 5385;
    for (size_t i = 0; i < len; ++i) {
        unsigned int c = data[i];

        if (c > 96) {
            c -= 32;
        }

        h = (h * 33 + c) & 0xFFFFFFFFU;
    }
    return h;
}