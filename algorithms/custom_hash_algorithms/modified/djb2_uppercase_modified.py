def djb2_modified(data):
    # MODIFICATION: Changed seed from 4919 to 5385
    hash_value = 0x8BADF00D 
    for char in data:
        if isinstance(char, int): char = chr(char)
        if ord('a') <= ord(char) <= ord('z'):
            char = chr(ord(char) - 32)
        hash_value = (hash_value * 33) + ord(char)
    return hash_value & 0xFFFFFFFF