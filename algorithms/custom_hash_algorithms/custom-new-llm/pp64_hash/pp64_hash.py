import sys
import os

# --- 1. The Algorithm (PP-64) ---
def pp64_hash(api_name):
    """
    PP-64 (Prime-Pervasive 64-bit).
    Uses a dynamic multiplier that evolves with the string.
    """
    # Initialization
    h = 0x14650FB0739D0383
    dynamic_prime = 0x100000001b3 # Starting prime
    
    # The Loop
    for char in api_name:
        # Normalize to uppercase
        if 'a' <= char <= 'z':
            char = chr(ord(char) - 32)
            
        c_val = ord(char)
        
        # Mix the hash
        h ^= c_val
        h = (h * dynamic_prime) & 0xFFFFFFFFFFFFFFFF
        
        # Evolve the prime based on the character and previous state
        # (This makes the sequence non-linear)
        dynamic_prime = (dynamic_prime + c_val + (h >> 32)) & 0xFFFFFFFFFFFFFFFF
        # Ensure it stays odd (even multipliers destroy entropy)
        dynamic_prime |= 1 

    # Finalizer (Simple XOR fold)
    h ^= h >> 27
    h = (h * 0x3C79AC492BA7B653) & 0xFFFFFFFFFFFFFFFF
    h ^= h >> 33
    
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
    print("=== API Hashing Simulation (PP-64) ===\n")

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
            h = pp64_hash(api)
            
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
    h1 = pp64_hash(s1)
    h2 = pp64_hash(s2)
    
    # XOR to find differing bits (Masked to 64 bits)
    diff = (h1 ^ h2) & 0xFFFFFFFFFFFFFFFF
    flipped_bits = bin(diff).count('1')
    
    print(f"    Input 1: {s1} -> {hex(h1)}")
    print(f"    Input 2: {s2} -> {hex(h2)}")
    print(f"    Bits Flipped: {flipped_bits}/64")
    
    if flipped_bits >= 24:
        print("    [+] PASS: Excellent avalanche effect (High Entropy).")
    else:
        print("    [-] FAIL: Still too correlated.")

if __name__ == "__main__":
    run_simulation()
    run_avalanche_check()