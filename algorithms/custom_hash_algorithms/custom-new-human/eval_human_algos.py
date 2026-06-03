import sys
import os

# =============================================================
# 1. Custom Algorithm 1: SAX-32 (Shift-Add-XOR)
# =============================================================
def sax32_hash(api_name):
    h = 0x55555555 # Custom Seed
    for char in api_name:
        c_val = ord(char)
        mixed = ((h << 5) ^ (h >> 3)) & 0xFFFFFFFF
        h = (mixed + c_val) & 0xFFFFFFFF
    return h

# =============================================================
# 2. Custom Algorithm 2: PS-32 (Prime-Subtract)
# =============================================================
def ps32_hash(api_name):
    h = 0x87654321 # Custom Seed
    for char in api_name:
        c_val = ord(char)
        h = ((h * 131) - c_val) & 0xFFFFFFFF
    return h

# =============================================================
# 3. Custom Algorithm 3: RA-32 (Rotate-Add)
# =============================================================
def ra32_hash(api_name):
    h = 0x0987ABCD # Custom Seed
    for char in api_name:
        c_val = ord(char)
        rol = ((h << 7) | (h >> 25)) & 0xFFFFFFFF
        h = (rol + c_val) & 0xFFFFFFFF
    return h

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

def evaluate_custom_algorithm(name, hash_func, api_list):
    print(f"--- Evaluating Custom Algorithm: {name} ---")
    
    seen_hashes = {}
    collisions = 0
    
    for api in api_list:
        h = hash_func(api)
        if h in seen_hashes:
            collisions += 1
        else:
            seen_hashes[h] = api

    if collisions == 0:
        print(f"    [+] COLLISION TEST: 0 collisions detected across {len(api_list)} APIs.\n")
    else:
        print(f"    [-] COLLISION TEST: {collisions} collisions detected.\n")

def run_simulation():
    print("=== Custom Human-Made Algorithms Evaluation ===\n")
    
    target_dlls = ["kernel32.dll", "user32.dll", "ntdll.dll"]
    all_apis = []
    
    print("[*] Extracting Windows APIs...")
    for dll in target_dlls:
        all_apis.extend(get_dll_exports(dll))
        
    all_apis = list(set(all_apis)) 
    print(f"[*] Total unique APIs extracted: {len(all_apis)}\n")
    
    if not all_apis:
        print("[!] No APIs loaded. Exiting.")
        return

    evaluate_custom_algorithm("SAX-32 (Shift-Add-XOR)", sax32_hash, all_apis)
    evaluate_custom_algorithm("PS-32 (Prime-Subtract)", ps32_hash, all_apis)
    evaluate_custom_algorithm("RA-32 (Rotate-Add)", ra32_hash, all_apis)

if __name__ == "__main__":
    run_simulation()