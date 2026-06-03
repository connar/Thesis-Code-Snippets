import sys
import os

# =============================================================
# 1. LLM Algorithm 1: RXM64 (Rotate-XOR-Multiply)
# =============================================================
def rotr64(n, bits):
    return ((n >> bits) | (n << (64 - bits))) & 0xFFFFFFFFFFFFFFFF

def rxm64_hash(api_name):
    h = 0xcbf29ce484222325
    prime = 0x100000001b3
    for char in api_name:
        if 'a' <= char <= 'z':
            char = chr(ord(char) - 32)
        h ^= ord(char)
        h = (h * prime) & 0xFFFFFFFFFFFFFFFF
        h = rotr64(h, 13)

    h ^= h >> 33
    h = (h * 0xff51afd7ed558ccd) & 0xFFFFFFFFFFFFFFFF
    h ^= h >> 33
    h = (h * 0xc4ceb9fe1a85ec53) & 0xFFFFFFFFFFFFFFFF
    h ^= h >> 33
    return h

# =============================================================
# 2. LLM Algorithm 2: XSA-32 (XOR-Shift-Add)
# =============================================================
def xsa32_hash(api_name):
    h = 0x811C9DC5 
    for char in api_name:
        if 'A' <= char <= 'Z':
            char = chr(ord(char) + 32)
        c_val = ord(char)
        h = (h + c_val) & 0xFFFFFFFF
        h ^= (h << 13) & 0xFFFFFFFF
        h ^= (h >> 17) & 0xFFFFFFFF
        h ^= (h << 5)  & 0xFFFFFFFF

    h = (h + (h << 3)) & 0xFFFFFFFF
    h ^= (h >> 11) & 0xFFFFFFFF
    h = (h + (h << 15)) & 0xFFFFFFFF
    return h

# =============================================================
# 3. LLM Algorithm 3: PP-64 (Prime-Pervasive)
# =============================================================
def pp64_hash(api_name):
    h = 0x14650FB0739D0383
    dynamic_prime = 0x100000001b3 
    for char in api_name:
        if 'a' <= char <= 'z':
            char = chr(ord(char) - 32)
        c_val = ord(char)
        h ^= c_val
        h = (h * dynamic_prime) & 0xFFFFFFFFFFFFFFFF
        dynamic_prime = (dynamic_prime + c_val + (h >> 32)) & 0xFFFFFFFFFFFFFFFF
        dynamic_prime |= 1 

    h ^= h >> 27
    h = (h * 0x3C79AC492BA7B653) & 0xFFFFFFFFFFFFFFFF
    h ^= h >> 33
    return h

# =============================================================
# Testing Logic
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

def evaluate_llm_algorithm(name, hash_func, api_list):
    print(f"--- Evaluating {name} ---")
    
    seen_hashes = {}
    collisions = 0
    
    for api in api_list:
        h = hash_func(api)
        if h in seen_hashes:
            collisions += 1
        else:
            seen_hashes[h] = api

    if collisions == 0:
        print(f"    [+] COLLISION TEST: 0 collisions across {len(api_list)} APIs.\n")
    else:
        print(f"    [-] COLLISION TEST: {collisions} collisions detected.\n")

def run_simulation():
    print("=== LLM-Generated Algorithms Evaluation ===\n")
    
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

    evaluate_llm_algorithm("RXM64 (64-bit)", rxm64_hash, all_apis)
    evaluate_llm_algorithm("XSA-32 (32-bit)", xsa32_hash, all_apis)
    evaluate_llm_algorithm("PP-64 (64-bit)", pp64_hash, all_apis)

if __name__ == "__main__":
    run_simulation()