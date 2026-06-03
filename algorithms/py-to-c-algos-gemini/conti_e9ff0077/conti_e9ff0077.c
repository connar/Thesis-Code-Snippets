#include <stdint.h>
#include <stddef.h>

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t hash_val = 0;
    uint32_t v15 = 0xE9FF0077U;
    size_t API_buffer_count = 0;
    size_t len_orig = len;

    if (len >= 4) {
        size_t count = len >> 2;

        while (count > 0) {
            uint32_t temp_buffer_val =
                ((uint32_t)data[API_buffer_count + 3] << 24) |
                ((uint32_t)data[API_buffer_count + 2] << 16) |
                ((uint32_t)data[API_buffer_count + 1] << 8) |
                ((uint32_t)data[API_buffer_count]);

            uint32_t temp = 0x5BD1E995U * temp_buffer_val;
            API_buffer_count += 4;
            v15 = (0x5BD1E995U * (temp ^ (temp >> 24))) ^ (0x5BD1E995U * v15);
            count--;
        }
    }

    size_t remaining_bytes = len_orig & 3; // len_orig % 4
    switch (remaining_bytes) {
        case 3:
            hash_val ^= ((uint32_t)data[API_buffer_count + 2] << 16);
            // Fallthrough
        case 2:
            hash_val ^= ((uint32_t)data[API_buffer_count + 1] << 8);
            // Fallthrough
        case 1:
            hash_val ^= ((uint32_t)data[API_buffer_count]);
            break;
        case 0:
            // hash_val remains 0
            break;
    }

    uint32_t v20 = 0x5BD1E995U * hash_val;
    uint32_t edi = 0x5BD1E995U * (uint32_t)len_orig;

    uint32_t eax = v20 >> 24;
    eax ^= v20;

    uint32_t ecx = 0x5BD1E995U * eax;
    eax = 0x5BD1E995U * v15;

    ecx ^= eax;

    eax = edi;
    eax >>= 24;
    eax ^= edi;

    uint32_t edx = 0x5BD1E995U * ecx;
    eax = 0x5BD1E995U * eax;
    edx ^= eax;
    eax = edx;

    eax >>= 13;
    eax ^= edx;

    ecx = 0x5BD1E995U * eax;
    eax = ecx;
    eax >>= 15;
    eax ^= ecx;

    return eax;
}