#include <stdint.h>
#include <ctype.h>

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t hash_val = 0;
    uint32_t u32_len = (uint32_t)len;

    for (size_t i = 0; i < len; ++i) {
        uint8_t begin_chr = data[i];
        uint32_t begin_chr_upper = (uint32_t)toupper((unsigned char)begin_chr);

        uint8_t end_chr;
        if (i == len - 1) {
            end_chr = data[0];
        } else {
            end_chr = data[len - i - 2];
        }
        uint32_t end_chr_upper = (uint32_t)toupper((unsigned char)end_chr);

        uint32_t v16 = ((uint32_t)begin_chr ^ u32_len);
        uint32_t v18 = ((uint32_t)end_chr ^ u32_len);
        uint32_t v17 = ((uint32_t)begin_chr_upper ^ u32_len);
        uint32_t v15 = ((uint32_t)end_chr_upper ^ u32_len);

        uint64_t product = (uint64_t)v17 * v18 * v16;
        uint32_t sum_and_masked = (uint32_t)(hash_val + product);

        hash_val = v15 ^ sum_and_masked;
    }

    return hash_val;
}