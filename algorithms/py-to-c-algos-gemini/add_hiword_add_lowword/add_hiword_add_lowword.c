#include <stdint.h>
#include <stddef.h>

uint32_t hash(const unsigned char* data, size_t len) {
    unsigned int hash_high = 0xffff;
    unsigned int hash_low = 0xffff;

    for (size_t ptr = 0; ptr < len; ++ptr) {
        hash_low = (hash_low + (unsigned int)data[ptr]);
        hash_high = (hash_high + hash_low);
    }

    hash_high %= 0xFFF1;
    hash_low %= 0xFFF1;

    return ((uint32_t)hash_high << 16) + (uint32_t)hash_low;
}