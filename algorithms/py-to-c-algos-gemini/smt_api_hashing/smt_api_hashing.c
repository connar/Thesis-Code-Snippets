#include <stdint.h> // For uint32_t, int32_t, uint8_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t h = 0x2DBB955; // Seed value

    for (size_t i = 0; i < len; ++i) {
        uint8_t char_byte = data[i];
        
        // Convert unsigned byte to its signed 8-bit equivalent.
        // This correctly handles values >= 128 by converting them
        // to their negative two's complement representation.
        int8_t signed_char_val = (int8_t)char_byte;

        // Treat 'h' as a signed 32-bit integer for the shift and multiplication
        // to ensure arithmetic right shift behavior.
        int32_t signed_h = (int32_t)h;
        
        // Perform arithmetic right shift.
        int32_t s = signed_h >> 2;
        
        // Standard multiplication.
        int32_t m = signed_h * 32;
        
        // Sum the components. The result will be an int32_t.
        int32_t right_side = signed_char_val + s + m;

        // XOR 'h' with 'right_side'. Cast 'right_side' to uint32_t
        // to ensure the XOR operation is performed on unsigned 32-bit values.
        // The explicit mask '& 0xFFFFFFFF' ensures the result is truncated
        // to 32 bits, mimicking Python's behavior.
        h = (h ^ (uint32_t)right_side) & 0xFFFFFFFF;
    }
   
    return h;
}