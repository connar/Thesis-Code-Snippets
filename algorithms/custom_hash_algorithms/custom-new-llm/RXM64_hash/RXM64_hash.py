import sys
import os

# --- 1. The Improved Algorithm (RXM64-Finalized) ---
def rotr64(n, bits):
    """Rotates a 64-bit integer right by 'bits' positions."""
    return ((n >> bits) | (n << (64 - bits))) & 0xFFFFFFFFFFFFFFFF

def rxm64_hash(api_name):
    """
    RXM64 (Rotate-XOR-Multiply) with Finalizer.
    Designed for Windows API Hashing.
    """
    # 1. Initialization (FNV Offset Basis)
    h = 0xcbf29ce484222325
    prime = 0x100000001b3
    
    # 2. The Loop (Iterative Mixing)
    for char in api_name:
        # Normalize to uppercase (Windows Loader Standard)
        if 'a' <= char <= 'z':
            char = chr(ord(char) - 32)
        
        # Mix: XOR -> Multiply -> Rotate
        h ^= ord(char)
        h = (h * prime) & 0xFFFFFFFFFFFFFFFF
        h = rotr64(h, 13)

    # 3. The Finalizer (The Avalanche Fix)
    # This block forces the last few bytes to affect the ENTIRE 64-bit state.
    
    # Fold high bits down
    h ^= h >> 33
    # Multiply by a mixer constant (Murmur3 mixer)
    h = (h * 0xff51afd7ed558ccd) & 0xFFFFFFFFFFFFFFFF
    # Fold high bits down again
    h ^= h >> 33
    # One last multiply for good measure
    h = (h * 0xc4ceb9fe1a85ec53) & 0xFFFFFFFFFFFFFFFF
    h ^= h >> 33
    
    return h

# --- 2. PEB Walking Simulation ---
def get_dll_exports(dll_name):
    """
    Simulates finding a DLL in memory and parsing its Export Address Table (EAT).
    Uses 'pefile' to parse the DLL from disk for this simulation.
    """
    # Try to find the DLL in the System32 folder
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
    print("=== API Hashing Simulation (RXM64-Finalized) ===\n")

    # The DLLs typically loaded in a standard process (accessible via PEB)
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
            h = rxm64_hash(api)
            
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
    h1 = rxm64_hash(s1)
    h2 = rxm64_hash(s2)
    
    # XOR to find differing bits
    diff = h1 ^ h2
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