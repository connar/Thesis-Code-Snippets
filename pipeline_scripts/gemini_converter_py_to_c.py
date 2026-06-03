import os
import time
import re
import random
import shutil
import string
from google import genai
from google.genai import types
import subprocess

# ================= CONFIGURATION =================
# PASTE YOUR NEW "FREE TIER" KEY HERE
GEMINI_API_KEY = "yourownkey" 

# We use 1.5-flash because it allows 15 requests/min for free.
# The '002' version is the latest stable release.
MODEL_NAME = "gemini-2.5-flash"
ALGO_FOLDER = "./algorithms"
OUTPUT_DIR = "./py-to-c-algos-gemini"

# Initialize Client
client = genai.Client(api_key=GEMINI_API_KEY)

def check_api_key():
    """Verifies the API key and Model before starting."""
    print("[*] Checking API Key and Model access...")
    try:
        client.models.generate_content(
            model=MODEL_NAME, 
            contents="Test"
        )
        print("    [+] API Key is working. Quota is available.")
        return True
    except Exception as e:
        print(f"    [!] API Key Error: {e}")
        if "429" in str(e):
            print("        -> Your key is rate limited. Try a new key from a NEW project.")
        if "Precondition" in str(e) or "Billing" in str(e):
            print("        -> Your project has a billing issue. Create a key in a NEW project.")
        return False

def generate_test_vectors(num=5):
    vectors = []
    # Printable ASCII (0x20 - 0x7E) to avoid encoding issues
    printable_chars = string.ascii_letters + string.digits + string.punctuation + " "
    for _ in range(num):
        length = random.randint(8, 32)
        chars = ''.join(random.choices(printable_chars, k=length))
        vectors.append(chars.encode('utf-8'))
    return vectors

def detect_return_type(python_code):
    c_type = "uint32_t"
    print_fmt = "0x%x"
    match = re.search(r"TYPE\s*=\s*['\"](.*?)['\"]", python_code)
    if match:
        type_str = match.group(1).lower()
        if "64" in type_str or "long" in type_str:
            c_type = "uint64_t"
            print_fmt = "0x%llx"
    return c_type, print_fmt

def clean_code_string(code_str):
    # Remove markdown ```c and ```
    code_str = re.sub(r"^```[a-z]*\s*", "", code_str, flags=re.MULTILINE)
    code_str = re.sub(r"\s*```$", "", code_str, flags=re.MULTILINE)
    # Remove shebangs
    lines = code_str.splitlines()
    lines = [l for l in lines if not l.startswith("#!")]
    return "\n".join(lines).strip()

def get_c_code_from_gemini(python_code, c_type_return):
    prompt = (
        f"Convert the following Python hashing algorithm to C.\n\n"
        f"Input Python Code:\n{python_code}\n\n"
        f"Requirements:\n"
        f"1. The function signature MUST be strictly: '{c_type_return} hash(const unsigned char* data, size_t len)'.\n"
        f"2. STRICTLY use 'uint8_t' or 'unsigned char' for data bytes. NEVER use 'char'.\n"
        f"3. When XORing/Adding bytes, cast to (unsigned int) first to avoid sign extension.\n"
        f"4. If using toupper/tolower, include <ctype.h> and cast input to (unsigned char).\n"
        f"5. Ensure integer overflow mimics Python behavior (mask with 0xFFFFFFFF if returning 32-bit).\n"
        f"6. Do NOT use external libraries (zlib, openssl). Implement logic manually.\n"
        f"7. Provide ONLY the C code. No markdown, no explanations.\n"
        f"8. When looping with len - X, explicitly check if (len >= X) first to prevent unsigned integer underflow on small inputs.\n"
    )

    # Retry logic for 429 Rate Limits
    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=prompt,
                config=types.GenerateContentConfig(temperature=0.1)
            )
            return clean_code_string(response.text)

        except Exception as e:
            if "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e):
                wait_time = 20 * (attempt + 1)
                print(f"    [!] Rate Limit hit. Waiting {wait_time}s...")
                time.sleep(wait_time)
                continue
            else:
                print(f"    [!] Gemini Error: {e}")
                return None
    return None

def wrap_python_for_execution(original_code, test_vectors):
    vectors_repr = repr(test_vectors)
    wrapper = f"""
{original_code}

if __name__ == "__main__":
    test_vectors = {vectors_repr}
    import sys
    
    target_func = None
    if 'hash' in globals():
        target_func = globals()['hash']
    else:
        current_module = sys.modules[__name__]
        funcs = [obj for name, obj in current_module.__dict__.items() 
                 if callable(obj) and not name.startswith('__') 
                 and name not in ['ror', 'rol']]
        if funcs: target_func = funcs[0]
    
    if target_func:
        for vec in test_vectors:
            try:
                try:
                    val = target_func(vec)
                except (UnicodeDecodeError, TypeError):
                    val = target_func(vec.decode('utf-8'))

                if hasattr(val, 'value'): val = val.value
                
                if val is not None:
                    print(f"0x{{int(val):x}}")
                else:
                    print("Error: None")
            except Exception as e:
                print(f"Error: {{e}}")
    else:
        print("Error: No function found")
"""
    return wrapper

def wrap_c_for_execution(c_code, test_vectors, print_fmt):
    c_code_clean = re.sub(r"int\s+main\s*\(.*?\)\s*\{.*?\}", "", c_code, flags=re.DOTALL)
    
    main_body = ""
    for i, vec in enumerate(test_vectors):
        hex_arr = ", ".join(f"0x{b:02x}" for b in vec)
        var_name = f"vec_{i}"
        main_body += f"    unsigned char {var_name}[] = {{ {hex_arr} }};\n"
        main_body += f"    printf(\"{print_fmt}\\n\", (unsigned long long)hash({var_name}, {len(vec)}));\n"

    wrapper = f"""
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

{c_code_clean}

int main() {{
{main_body}
    return 0;
}}
"""
    return wrapper

def run_experiment():
    if not check_api_key():
        return

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        
    files = [f for f in os.listdir(ALGO_FOLDER) if f.endswith(".py")]
    files.sort()
    
    print(f"\n[*] Found {len(files)} algorithms. Using Gemini 1.5 Flash.\n")

    for i, fname in enumerate(files):
        algo_name = fname.replace(".py", "")
        save_dir = os.path.join(OUTPUT_DIR, algo_name)
        
        if os.path.exists(save_dir):
            continue
            
        print(f"[{i+1}/{len(files)}] Processing: {algo_name}")
        
        with open(os.path.join(ALGO_FOLDER, fname), "r") as f:
            py_logic = f.read()

        c_type, print_fmt = detect_return_type(py_logic)

        c_logic = get_c_code_from_gemini(py_logic, c_type)
        if not c_logic:
            print("    [!] Failed to get C code.")
            continue

        vectors = generate_test_vectors(5)

        with open("temp_exec.py", "w") as f:
            f.write(wrap_python_for_execution(py_logic, vectors))
        
        with open("temp_exec.c", "w") as f:
            f.write(wrap_c_for_execution(c_logic, vectors, print_fmt))
        
        res = subprocess.run(["gcc", "temp_exec.c", "-o", "temp_exec"], capture_output=True, text=True)
        if res.returncode != 0:
            print(f"    [!] GCC Compilation Failed:\n{res.stderr}")
            continue

        try:
            py_proc = subprocess.run(["python3", "temp_exec.py"], capture_output=True, text=True)
            c_proc = subprocess.run(["./temp_exec"], capture_output=True, text=True)
            
            py_out = [l.strip().lower() for l in py_proc.stdout.strip().splitlines()]
            c_out = [l.strip().lower() for l in c_proc.stdout.strip().splitlines()]
            
            if len(py_out) == 5 and py_out == c_out and "error" not in py_out[0]:
                print("    [+] SUCCESS.")
                if not os.path.exists(save_dir):
                    os.makedirs(save_dir)
                shutil.copy(os.path.join(ALGO_FOLDER, fname), os.path.join(save_dir, fname))
                with open(os.path.join(save_dir, f"{algo_name}.c"), "w") as f:
                    f.write(c_logic)
            else:
                print("    [-] FAILURE: Mismatch.")
                if len(py_out) > 0 and len(c_out) > 0:
                    print(f"        Py: {py_out[0]}")
                    print(f"        C : {c_out[0]}")
                elif len(py_out) > 0:
                     print(f"        Py Error: {py_out[0]}")

        except Exception as e:
            print(f"    [!] Runtime Error: {e}")
        
        # Polite delay to respect the 15 RPM limit
        time.sleep(4)

    for f in ["temp_exec.py", "temp_exec.c", "temp_exec"]:
        if os.path.exists(f): os.remove(f)

if __name__ == "__main__":
    run_experiment()