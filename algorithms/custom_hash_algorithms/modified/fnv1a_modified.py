def fnv1a_modified(data):
    val = 0x811c9dc5
    for c in data:
        if isinstance(c, str): c = ord(c)
        val = (0x1000193 * (c ^ val)) & 0xffffffff
    # MODIFICATION: Post-calculation XOR
    return val ^ 0xDEADBEEF 