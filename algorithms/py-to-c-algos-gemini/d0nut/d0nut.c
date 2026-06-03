#include <stdint.h>
#include <stddef.h>

static uint32_t rol(uint32_t val, int r_bits, int max_bits) {
    int r_bits_mod = r_bits % max_bits;
    return (val << r_bits_mod) | (val >> (max_bits - r_bits_mod));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t hashcalc = 75569;

	if (len >= 4) {
		for (size_t pointer = 0; pointer <= len - 4; pointer += 4) {
			uint32_t shift_calc = (uint32_t)data[pointer+0] |
								  ((uint32_t)data[pointer+1] << 8) |
								  ((uint32_t)data[pointer+2] << 16) |
								  ((uint32_t)data[pointer+3] << 24);

			uint32_t term_e5438000 = (uint32_t)((uint64_t)0xE5438000 * shift_calc);
			uint32_t term_85ebca87 = (uint32_t)((uint64_t)0x85EBCA87 * shift_calc);
			
			uint32_t inner_or_part = term_e5438000 | (term_85ebca87 >> 17);
			
			uint32_t mul_27d4eb4f = (uint32_t)((uint64_t)0x27D4EB4F * inner_or_part);
			
			uint32_t rol_input = hashcalc ^ mul_27d4eb4f;
			
			uint32_t rol_result = rol(rol_input, 13, 32);
			
			hashcalc = (5 * rol_result) - 1640531463;
		}
	}
	
    uint32_t remainder_bytes = 0;
    size_t remainder = len % 4;
    if (remainder > 0) {
        for (size_t i = 0; i < remainder; ++i) {
            remainder_bytes |= ((uint32_t)data[len - remainder + i] << (i * 8));
        }
    }

    uint32_t rem_or_term_e5438000 = (uint32_t)((uint64_t)0xE5438000 * remainder_bytes);
    uint32_t rem_or_term_85ebca87 = (uint32_t)((uint64_t)0x85EBCA87 * remainder_bytes);
    
    uint32_t rem_or_inner_or_part = rem_or_term_e5438000 | (rem_or_term_85ebca87 >> 17);
    
    uint32_t rem_or_mul_27d4eb4f = (uint32_t)((uint64_t)0x27D4EB4F * rem_or_inner_or_part);
    
    uint32_t rem_or = rem_or_mul_27d4eb4f ^ (hashcalc ^ (uint32_t)len);

    uint32_t temp1 = rem_or ^ (rem_or >> 16);
    uint32_t mul_c2b2ae63_temp1 = (uint32_t)((uint64_t)0xC2B2AE63 * temp1);
    uint32_t temp2 = mul_c2b2ae63_temp1 ^ (mul_c2b2ae63_temp1 >> 13);
    uint32_t rem_hash = (uint32_t)((uint64_t)0x165667C5 * temp2);
    rem_hash = rem_hash ^ (rem_hash >> 16);

    return rem_hash;
}