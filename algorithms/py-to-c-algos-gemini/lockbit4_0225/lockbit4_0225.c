#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t
#include <ctype.h>  // For tolower

uint32_t hash(const unsigned char* data, size_t len) {
    const uint32_t MASK_32BIT = 0xFFFFFFFFU;
    uint32_t hash_value = 0x14bfU;
    uint32_t char_index = 0;

    for (size_t i = 0; i < len; ++i) {
        // Requirement 3: When XORing/Adding bytes, cast to (unsigned int) first to avoid sign extension.
        // uint32_t is an unsigned integer type, so casting data[i] to uint32_t fulfills this.
        uint32_t char_code = (uint32_t)data[i];
        
        // Python logic for normalization:
        // if 0x41 <= char_code <= 0x5A:
        //     normalized_char = (char_code + 0x20) & MASK_32BIT
        // else:
        //     normalized_char = char_code
        //
        // Requirement 4: If using toupper/tolower, include <ctype.h> and cast input to (unsigned char).
        // tolower correctly converts uppercase ASCII letters to lowercase and leaves other characters unchanged.
        // The result of tolower is an int, which is then cast to uint32_t.
        // For ASCII characters, char_code + 0x20 will not exceed 255, so no overflow requiring MASK_32BIT here.
        uint32_t normalized_char = (uint32_t)tolower((unsigned char)char_code);

        uint32_t index_modifier;
        if (char_index == 0) {
            index_modifier = 0;
        } else {
            // Python: index_modifier = (char_index ^ 0x14bf) & MASK_32BIT
            // In C, for uint32_t types, bitwise XOR operations naturally wrap around,
            // which is equivalent to masking with 0xFFFFFFFFU.
            index_modifier = char_index ^ 0x14bfU;
        }

        // Core hash calculation, broken down to explicitly apply MASK_32BIT where Python does.
        // Python: hash_value = (index_modifier * (((char_index + 0x14bf) * normalized_char + (hash_value ^ normalized_char)) & MASK_32BIT) + normalized_char) & MASK_32BIT

        // Calculate (char_index + 0x14bf)
        uint32_t term_char_index_plus_const = char_index + 0x14bfU;

        // Calculate (char_index + 0x14bf) * normalized_char
        uint32_t term_product_1 = term_char_index_plus_const * normalized_char;

        // Calculate (hash_value ^ normalized_char)
        uint32_t term_xor = hash_value ^ normalized_char;

        // Calculate term_product_1 + term_xor
        uint32_t inner_sum = term_product_1 + term_xor;

        // Requirement 5: Ensure integer overflow mimics Python behavior (mask with 0xFFFFFFFF if returning 32-bit).
        // Python explicitly applies `& MASK_32BIT` at this point.
        uint32_t masked_inner_sum = inner_sum & MASK_32BIT;

        // Calculate index_modifier * masked_inner_sum
        uint32_t product_outer = index_modifier * masked_inner_sum;

        // Calculate product_outer + normalized_char
        uint32_t final_sum = product_outer + normalized_char;

        // Requirement 5: Python explicitly applies `& MASK_32BIT` to the final result.
        hash_value = final_sum & MASK_32BIT;

        char_index++;
    }

    return hash_value;
}