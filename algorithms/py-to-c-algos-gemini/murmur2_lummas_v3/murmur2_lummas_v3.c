#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t seed = 0x20;
    uint32_t seeded_len = ((uint32_t)len ^ seed);

    // Variables for intermediate calculations, always uint32_t to handle 32-bit operations
    uint32_t eax_val;
    uint32_t ecx_val;

    // The Python code's structure dictates that block and tail processing
    // only occur if the input length is greater than 4.
    if (len > 4) {
        // Calculate the number of 4-byte blocks
        uint32_t num_blocks = (uint32_t)len >> 2; // Equivalent to fun_len >> 2 & 0xFFFFFFFF
        size_t new_index = 0; // To store the starting index of the remaining tail bytes

        // Process 4-byte blocks
        for (size_t i = 0; i < num_blocks; ++i) {
            size_t current_data_idx = i * 4;

            // seeded_len = (seeded_len * 0x5BD1E995) & 0xFFFFFFFF
            seeded_len = (seeded_len * 0x5BD1E995);

            // ecx = ((((((data[i+3] << 8) | data[i+2]) << 8) | data[i+1]) << 8 | data[i]) * 0x5BD1E995) & 0xFFFFFFFF
            // This constructs a 32-bit integer from 4 bytes in little-endian order.
            uint32_t k_val = (uint32_t)data[current_data_idx] |
                             ((uint32_t)data[current_data_idx + 1] << 8) |
                             ((uint32_t)data[current_data_idx + 2] << 16) |
                             ((uint32_t)data[current_data_idx + 3] << 24);

            ecx_val = (k_val * 0x5BD1E995);

            // eax = ecx
            // eax = eax >> 0x18 & 0xFFFFFFFF
            // eax = (eax ^ ecx) & 0xFFFFFFFF
            eax_val = ecx_val;
            eax_val = eax_val >> 0x18;
            eax_val = (eax_val ^ ecx_val);

            // ecx = (eax * 0x5BD1E995) & 0xFFFFFFFF
            ecx_val = (eax_val * 0x5BD1E995);

            // seeded_len = (seeded_len ^ ecx) & 0xFFFFFFFF
            seeded_len = (seeded_len ^ ecx_val);

            new_index = current_data_idx + 4; // Update new_index for the start of the tail
        }

        // Tail processing for remaining bytes (len % 4)
        // Python's `fun_len` after block processing is `len - (4 * (len >> 2))`, which is `len % 4`.
        uint32_t remaining_len = (uint32_t)len % 4;
        const unsigned char* tail_ptr = data + new_index;

        if (remaining_len == 1) {
            // if (fun_len - 1) == 0:
            eax_val = ((uint32_t)tail_ptr[0] ^ seeded_len);
            seeded_len = (eax_val * 0x5BD1E995);
            return eax_val; // This is an unusual early return specific to the Python code
        } else if (remaining_len == 2) {
            // elif (fun_len - 2) == 0:
            eax_val = ((uint32_t)tail_ptr[1] << 8);
            seeded_len = seeded_len ^ eax_val;
            eax_val = (uint32_t)tail_ptr[0];
            eax_val = eax_val ^ seeded_len;
            seeded_len = (eax_val * 0x5BD1E995);
        } else if (remaining_len == 0) {
            // elif (fun_len - 3) != 0: (which means fun_len is not 3, and not 1 or 2, so it must be 0)
            // pass (do nothing)
        } else { // remaining_len == 3
            // else:
            eax_val = (uint32_t)tail_ptr[2];
            eax_val = eax_val << 0x10;
            seeded_len = (seeded_len ^ eax_val);
            eax_val = (uint32_t)tail_ptr[1];
            eax_val = (eax_val << 8);
            seeded_len = (seeded_len ^ eax_val);
            eax_val = (uint32_t)tail_ptr[0];
            eax_val = eax_val ^ seeded_len;
            seeded_len = (eax_val * 0x5BD1E995);
        }
    } // End of `if (len > 4)` block

    // Finalization steps (executed after block/tail processing, or directly if len <= 4)
    eax_val = seeded_len;
    eax_val = eax_val >> 0xD;
    eax_val = eax_val ^ seeded_len;
    ecx_val = (eax_val * 0x5BD1E995);
    eax_val = ecx_val;
    eax_val = (eax_val >> 0xF);
    eax_val = eax_val ^ ecx_val;

    return eax_val;
}