def sdbm_modified(data):
    hsh = 0
    for d in data:
        if isinstance(d, str): d = ord(d)
        hsh = d + 0x1003f * hsh
        # Force 64-bit truncation before shifting
        hsh &= 0xffffffffffffffff
        # MODIFICATION: In-loop shift and XOR
        hsh ^= (hsh >> 13) 
    return hsh & 0xffffffffffffffff