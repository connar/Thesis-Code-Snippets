#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

/**
 * @brief Rotates a 32-bit unsigned integer left by a specified number of shifts.
 *
 * This function emulates the rotate left (ROL) instruction for a 32-bit value.
 * It is a helper function for the hashing algorithm.
 *
 * @param inVal The 32-bit unsigned integer to rotate.
 * @param numShifts The number of bits to rotate left.
 * @return The rotated 32-bit unsigned integer.
 */
static uint32_t rol(uint32_t inVal, int numShifts) {
    // For this specific hashing algorithm, dataSize is always 32.
    const int dataSize = 32;
    return (inVal << numShifts) | (inVal >> (dataSize - numShifts));
}

/**
 * @brief Implements a custom hashing algorithm based on ROL 7, ADD, and XOR 2.
 *
 * This function computes a 32-bit hash value for a given byte array.
 * The algorithm iterates through each byte of the input data, performing
 * a rotate left operation, an XOR with 2, and an addition.
 *
 * @param data A pointer to the input byte array.
 * @param len The length of the input byte array.
 * @return The computed 32-bit unsigned hash value.
 */
uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0; // Initialize hash value to 0

    // Iterate through each byte of the input data
    for (size_t i = 0; i < len; ++i) {
        // 1. Rotate the current hash value left by 7 bits
        val = rol(val, 0x7);

        // 2. XOR the current data byte with 2, then add to the hash value
        // Cast data[i] to unsigned int to ensure proper integer promotion
        // and avoid sign extension issues before XORing and adding.
        val += ((unsigned int)data[i] ^ 2);
        // The addition to a uint32_t naturally handles 32-bit unsigned overflow,
        // mimicking Python's behavior with a 0xFFFFFFFF mask.
    }

    return val;
}