#include <stdint.h>
#include <stddef.h>

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t crc = 0xffffffff;

    for (size_t i = 0; i < len; ++i) {
        uint32_t val = (uint32_t)data[i];

        for (int j = 0; j < 8; ++j) {
            uint32_t tmp = crc;
            crc = crc >> 1;
            
            if (((val ^ tmp) & 1) != 0) {
                crc ^= 0xedb88320;
            }
            val = val >> 1;
        }
    }
    return crc;
}