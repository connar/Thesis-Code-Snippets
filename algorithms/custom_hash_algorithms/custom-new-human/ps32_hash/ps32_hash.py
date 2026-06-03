def ps32_hash(api_name):
    """
    Uses a standard hash prime (131) but subtracts the character
    value to diverge from standard additive hashes.
    """
    h = 0x87654321 # Custom Seed
    for char in api_name:
        c_val = ord(char)
        # Multiply by prime 131, subtract character
        h = ((h * 131) - c_val) & 0xFFFFFFFF
    return h