import sys
import os

# =============================================================
# 1. FNV-1a (Code Modification: Post-Calculation XOR)
# https://github.com/OALabs/hashdb/blob/main/algorithms/fnv1a.py
# =============================================================
def fnv1a_original(data):
    val = 0x811c9dc5
    for c in data:
        if isinstance(c, str): c = ord(c)
        val = (0x1000193 * (c ^ val)) & 0xffffffff
    return val

def fnv1a_modified(data):
    val = 0x811c9dc5
    for c in data:
        if isinstance(c, str): c = ord(c)
        val = (0x1000193 * (c ^ val)) & 0xffffffff
    # MODIFICATION: Post-calculation XOR
    return val ^ 0xDEADBEEF 

# =============================================================
# 2. SDBM 65599 x64 (Code Modification: In-Loop XOR Fold)
# https://github.com/OALabs/hashdb/blob/main/algorithms/sdbm_65599_x64.py
# =============================================================
def sdbm_original(data):
    hsh = 0
    for d in data:
        if isinstance(d, str): d = ord(d)
        hsh = d + 0x1003f * hsh
    return hsh & 0xffffffffffffffff

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

# =============================================================
# 3. DJB2 Uppercase (Seed Modification)
# https://github.com/OALabs/hashdb/blob/main/algorithms/djb2_uppercase.py
# =============================================================
def djb2_original(data):
    hash_value = 4919
    for char in data:
        if isinstance(char, int): char = chr(char)
        if ord('a') <= ord(char) <= ord('z'):
            char = chr(ord(char) - 32)
        hash_value = (hash_value * 33) + ord(char)
    return hash_value & 0xFFFFFFFF

def djb2_modified(data):
    # MODIFICATION: Changed seed from 4919 to 5385
    hash_value = 0x8BADF00D 
    for char in data:
        if isinstance(char, int): char = chr(char)
        if ord('a') <= ord(char) <= ord('z'):
            char = chr(ord(char) - 32)
        hash_value = (hash_value * 33) + ord(char)
    return hash_value & 0xFFFFFFFF



# =============================================================
# PEB Walk Simulation & Testing Logic
# =============================================================
def get_dll_exports(dll_name):
    system32 = os.path.join(os.environ['SystemRoot'], 'System32')
    dll_path = os.path.join(system32, dll_name)
    
    try:
        import pefile
    except ImportError:
        print("[!] Install pefile: pip install pefile")
        return []

    if not os.path.exists(dll_path):
        return []

    pe = pefile.PE(dll_path)
    exports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode('utf-8'))
    return exports

def evaluate_algorithm(name, original_func, modified_func, api_list):
    print(f"--- Evaluating {name} ---")
    
    seen_hashes_mod = {}
    collisions_mod = 0
    identical_hashes = 0
    
    # 1. Process every API in the list
    for api in api_list:
        orig_hash = original_func(api)
        mod_hash = modified_func(api)
        
        # Check if the modification actually produced a new hash
        if orig_hash == mod_hash:
            identical_hashes += 1
            
        # Check if the new modified hash causes collisions with other modified hashes
        if mod_hash in seen_hashes_mod:
            collisions_mod += 1
            # Uncomment below if you want to see exactly which APIs collided
            # print(f"       [!] Collision: {api} == {seen_hashes_mod[mod_hash]}")
        else:
            seen_hashes_mod[mod_hash] = api

    # 2. Print Summary of Modification Effectiveness
    if identical_hashes == 0:
        print(f"    [+] EVASION TEST: 100% of APIs ({len(api_list)}) yielded NEW hashes.")
    else:
        print(f"    [-] EVASION FAILED: {identical_hashes} APIs had identical hashes.")

    # 3. Print Summary of Collision Resistance
    if collisions_mod == 0:
        print(f"    [+] COLLISION TEST: 0 collisions detected.")
    else:
        print(f"    [-] COLLISION TEST: {collisions_mod} collisions detected.")

    # 4. Print one visual example
    example_api = "VirtualAlloc"
    if example_api in api_list:
        print(f"    Example ({example_api}):")
        print(f"      Original : {hex(original_func(example_api))}")
        print(f"      Modified : {hex(modified_func(example_api))}\n")
    else:
        print("\n")

def run_simulation():
    print("=== Modified HashDB Algorithms Evaluation ===\n")
    
    target_dlls = ["kernel32.dll", "user32.dll", "ntdll.dll"]
    all_apis = []
    
    print("[*] Extracting Windows APIs...")
    for dll in target_dlls:
        all_apis.extend(get_dll_exports(dll))
        
    all_apis = list(set(all_apis)) # Remove duplicates across forwarded exports
    print(f"[*] Total unique APIs extracted: {len(all_apis)}\n")
    
    if not all_apis:
        print("[!] No APIs loaded. Exiting.")
        return

    evaluate_algorithm("FNV-1a (Code Mod: Post-XOR)", fnv1a_original, fnv1a_modified, all_apis)
    evaluate_algorithm("SDBM 65599 (Code Mod: Loop Shift)", sdbm_original, sdbm_modified, all_apis)
    evaluate_algorithm("DJB2 Upper (Seed Mod: 4919 -> 5385)", djb2_original, djb2_modified, all_apis)

if __name__ == "__main__":
    run_simulation()