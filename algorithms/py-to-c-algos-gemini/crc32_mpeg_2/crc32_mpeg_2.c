#include <stddef.h> // For size_t
#include <stdint.h> // For uint32_t, uint8_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF; // Initial CRC value

    for (size_t i = 0; i < len; ++i) {
        uint8_t val = data[i]; // Get current byte

        // XOR the current CRC with the byte shifted left by 24 bits.
        // Cast val to uint32_t to ensure the shift operates on a 32-bit value
        // before XORing with crc.
        crc ^= (uint32_t)val << 24;

        for (int j = 0; j < 8; ++j) { // Inner loop runs 8 times (for each bit of the byte)
            // Check the most significant bit (MSB) of crc.
            // In C, for uint32_t, (crc << 1) naturally discards the 32nd bit (MSB).
            // The polynomial 0x104C11DB7 in Python implies a 32-bit polynomial
            // 0x04C11DB7, where the leading '1' represents the implicit x^32 term
            // that is handled by the overflow of the 32-bit register.
            if ((crc & 0x80000000) == 0) {
                crc = crc << 1;
            } else {
                crc = (crc << 1) ^ 0x04C11DB7;
            }
        }
    }
    return crc;
}