import sys
import os

# --- 1. The Algorithm (XSA-32) ---
def xsa32_hash(api_name):
    """
    XSA-32 (XOR-Shift-Add 32-bit).
    A fast, multiplication-free 32-bit hash.
    """
    # Initialization (Arbitrary Magic Number)
    h = 0x811C9DC5 
    
    # The Loop
    for char in api_name:
        # Normalize to lowercase (Alternative to uppercase)
        if 'A' <= char <= 'Z':
            char = chr(ord(char) + 32)
            
        c_val = ord(char)
        
        # Mix: Add -> XOR -> Left Shift -> Right Shift
        h = (h + c_val) & 0xFFFFFFFF
        h ^= (h << 13) & 0xFFFFFFFF
        h ^= (h >> 17) & 0xFFFFFFFF
        h ^= (h << 5)  & 0xFFFFFFFF

    # Finalizer (To ensure short strings distribute well)
    h = (h + (h << 3)) & 0xFFFFFFFF
    h ^= (h >> 11) & 0xFFFFFFFF
    h = (h + (h << 15)) & 0xFFFFFFFF
    
    return h

# --- 2. PEB Walking Simulation ---
def get_dll_exports(dll_name):
    """
    Simulates finding a DLL in memory and parsing its Export Address Table (EAT).
    Uses 'pefile' to parse the DLL from disk for this simulation.
    """
    system32 = os.path.join(os.environ['SystemRoot'], 'System32')
    dll_path = os.path.join(system32, dll_name)
    
    try:
        import pefile
    except ImportError:
        print(f"[!] Error: 'pefile' library is missing. Install it with: pip install pefile")
        return []

    if not os.path.exists(dll_path):
        print(f"[!] DLL not found at: {dll_path}")
        return []

    try:
        pe = pefile.PE(dll_path)
    except Exception as e:
        print(f"[!] Error parsing {dll_name}: {e}")
        return []

    exports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode('utf-8'))
    
    return exports

# --- 3. Testing Logic ---
def run_simulation():
    print("=== API Hashing Simulation (XSA-32) ===\n")

    target_dlls = ["kernel32.dll", "user32.dll", "ntdll.dll"]
    
    for dll in target_dlls:
        print(f"[*] Simulating PEB walk for: {dll}...")
        api_list = get_dll_exports(dll)
        
        if not api_list:
            print(f"    [!] No exports found or file missing.\n")
            continue

        hashes = {}
        collisions = 0
        
        print(f"    -> Parsing {len(api_list)} exports...")
        
        for api in api_list:
            h = xsa32_hash(api)
            
            if h in hashes:
                collisions += 1
                print(f"       [!] COLLISION: {api} collides with {hashes[h]} (Hash: {hex(h)})")
            else:
                hashes[h] = api
                
        print(f"    -> Unique Hashes: {len(hashes)}")
        print(f"    -> Collisions: {collisions}")
        
        if collisions == 0:
            print(f"    [+] PERFECT MAP: No collisions for {dll}.")
        else:
            print(f"    [-] WARNING: Collisions detected.")
        print("-" * 40)

def run_avalanche_check():
    print("\n[*] Running Avalanche Test (Fix Verification)...")
    s1, s2 = "CreateFileA", "CreateFileB"
    h1 = xsa32_hash(s1)
    h2 = xsa32_hash(s2)
    
    # XOR to find differing bits (Masked to 32 bits)
    diff = (h1 ^ h2) & 0xFFFFFFFF
    flipped_bits = bin(diff).count('1')
    
    print(f"    Input 1: {s1} -> {hex(h1)}")
    print(f"    Input 2: {s2} -> {hex(h2)}")
    print(f"    Bits Flipped: {flipped_bits}/32")
    
    if flipped_bits >= 12:
        print("    [+] PASS: Excellent avalanche effect (High Entropy).")
    else:
        print("    [-] FAIL: Still too correlated.")

if __name__ == "__main__":
    run_simulation()
    run_avalanche_check()