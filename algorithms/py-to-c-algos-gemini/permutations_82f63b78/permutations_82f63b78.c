#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

// Constant from Python code
#define POLY 0x82F63B78U

// Helper function for the common pattern: (shift_val >> 1) ^ (poly_const * (xor_val_lsb_source & 1))
static inline uint32_t calculate_step(uint32_t shift_val, uint32_t xor_val_lsb_source, uint32_t poly_const) {
    return (shift_val >> 1) ^ (poly_const * (xor_val_lsb_source & 1));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;

    for (size_t k = 0; k < len; ++k) {
        // Cast byte to uint32_t to ensure unsigned arithmetic and avoid sign extension
        uint32_t i = (uint32_t)data[k];

        // Python: v1 = ((((i | 0x20) ^ val) >> 1) ^ (0x82F63B78 * (((i | 0x20) ^ val) & 1))) & 0xffffffff
        uint32_t current_val_xor_source = (i | 0x20U) ^ val;
        uint32_t v1 = calculate_step(current_val_xor_source, current_val_xor_source, POLY);

        // Python: v2 = ((((v1 >> 1) ^ (0x82F63B78 * (v1 & 1))) >> 1) ^ (0x82F63B78 * (((v1 >> 1) ^ (0x78 * (v1 & 1))) & 1))) & 0xffffffff
        // This can be broken down into:
        // A = (v1 >> 1) ^ (POLY * (v1 & 1))
        // B = (v1 >> 1) ^ (0x78 * (v1 & 1))
        // v2 = (A >> 1) ^ (POLY * (B & 1))
        uint32_t T_shift_val_v2 = calculate_step(v1, v1, POLY);
        uint32_t T_xor_lsb_source_v2 = (v1 >> 1) ^ (0x78U * (v1 & 1));
        uint32_t v2 = calculate_step(T_shift_val_v2, T_xor_lsb_source_v2, POLY);

        // Python: v3 = ((((v2 >> 1) ^ (0x82F63B78 * (v2 & 1))) >> 1) ^ (0x82F63B78 * (((v2 >> 1) ^ (0x78 * (v2 & 1))) & 1))) & 0xffffffff
        // Same structure as v2, but with v2 as input
        uint32_t T_shift_val_v3 = calculate_step(v2, v2, POLY);
        uint32_t T_xor_lsb_source_v3 = (v2 >> 1) ^ (0x78U * (v2 & 1));
        uint32_t v3 = calculate_step(T_shift_val_v3, T_xor_lsb_source_v3, POLY);

        // Python: v4 = ((((v3 >> 1) ^ (0x82F63B78 * (v3 & 1))) >> 1) ^ (0x82F63B78 * (((v3 >> 1) ^ (0x78 * (v3 & 1))) & 1))) & 0xffffffff
        // Same structure as v2, v3, but with v3 as input
        uint32_t T_shift_val_v4 = calculate_step(v3, v3, POLY);
        uint32_t T_xor_lsb_source_v4 = (v3 >> 1) ^ (0x78U * (v3 & 1));
        uint32_t v4 = calculate_step(T_shift_val_v4, T_xor_lsb_source_v4, POLY);

        // Python: val = ((v4 >> 1) ^ (0x82F63B78 * (v4 & 1))) & 0xffffffff
        val = calculate_step(v4, v4, POLY);
    }

    // Python: return val ^ 0xBC
    return val ^ 0xBCU;
}