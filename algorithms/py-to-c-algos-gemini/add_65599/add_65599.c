#include <stdint.h>
#include <stddef.h>

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t result = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = data[i];
        
        uint32_t tmp = (uint32_t)c + 32;
        
        if ((((int)c - (int)'A') & 0xFFFF) > 26) {
            tmp = c;
        }
        
        uint64_t intermediate_product = (uint64_t)0x1003F * result;
        uint64_t intermediate_sum = (uint64_t)tmp + intermediate_product;
        
        result = (uint32_t)intermediate_sum;
    }
    
    return result;
}