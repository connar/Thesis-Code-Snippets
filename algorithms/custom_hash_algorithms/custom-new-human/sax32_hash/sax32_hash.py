def sax32_hash(api_name):
    """
    Mixes bits by shifting left and right, then XORing them together
    before adding the character value.
    """
    h = 0x55555555 # Custom Seed
    for char in api_name:
        c_val = ord(char)
        # Shift left by 5, shift right by 3, XOR them, then add char
        mixed = ((h << 5) ^ (h >> 3)) & 0xFFFFFFFF
        h = (mixed + c_val) & 0xFFFFFFFF
    return h