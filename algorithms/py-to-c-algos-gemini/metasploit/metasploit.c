#include <stdint.h>
#include <stddef.h>

static uint32_t ror(uint32_t dword, int bits) {
    return ((dword >> bits) | (dword << (32 - bits))) & 0xFFFFFFFF;
}

uint32_t hash(const unsigned char* data, size_t len) {
    // 1. Setup the Prefix "KERNEL32.DLL" + \0\0\0
    // KERNEL32.DLL is 12 chars. + 3 nulls = 15 chars total prefix.
    unsigned char prefix[] = {'K','E','R','N','E','L','3','2','.','D','L','L', 0, 0, 0};
    int prefix_len = 15;
    
    // 2. We don't need to actually concatenate a huge buffer, 
    // we can just run the hashing loop in two stages.
    
    // STAGE A: Hash the Module (KERNEL32.DLL\0\0\0)
    uint32_t module_hash = 0;
    for (int i = 0; i < prefix_len; ++i) {
        module_hash = ror(module_hash, 13);
        module_hash += prefix[i];
    }

    // STAGE B: Hash the API Name (The input 'data')
    uint32_t api_hash = 0;
    for (size_t i = 0; i < len; ++i) {
        api_hash = ror(api_hash, 13);
        api_hash += data[i];
    }

    // 3. Return the sum
    return (module_hash + api_hash) & 0xFFFFFFFF;
}