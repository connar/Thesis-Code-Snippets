#include <stdint.h>
#include <stddef.h>

// CRC-32 lookup table
static uint32_t crc32_table[256];
static int crc32_table_initialized = 0;

// Function to initialize the CRC-32 table
static void init_crc32_table() {
    if (!crc32_table_initialized) {
        uint32_t polynomial = 0xEDB88320; // IEEE 802.3 polynomial (reversed)

        for (int i = 0; i < 256; i++) {
            uint32_t crc = i;
            for (int j = 0; j < 8; j++) {
                if (crc & 1) {
                    crc = (crc >> 1) ^ polynomial;
                } else {
                    crc >>= 1;
                }
            }
            crc32_table[i] = crc;
        }
        crc32_table_initialized = 1;
    }
}

// Hashing function
uint32_t hash(const unsigned char* data, size_t len) {
    // Ensure the CRC table is initialized once
    init_crc32_table();

    uint32_t crc = 0xFFFFFFFF; // Initial CRC value

    for (size_t i = 0; i < len; i++) {
        // Cast data[i] to unsigned int before XORing to avoid sign extension issues,
        // as per requirement 3.
        crc = (crc >> 8) ^ crc32_table[(crc ^ (unsigned int)data[i]) & 0xFF];
    }

    // Final XOR with 0xFFFFFFFF
    return crc ^ 0xFFFFFFFF;
}