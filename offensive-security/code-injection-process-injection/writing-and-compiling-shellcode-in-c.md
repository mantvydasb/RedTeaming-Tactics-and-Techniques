# Writing and Compiling Shellcode in C

This is a quick lab to get familiar with the process of writing and compiling shellcode in C and is merely a personal conspectus of the paper [From a C project, through assembly, to shellcode](https://vxug.fakedoma.in/papers/VXUG/Exclusive/FromaCprojectthroughassemblytoshellcodeHasherezade.pdf) by [hasherezade](https://twitter.com/hasherezade) for [vxunderground](https://twitter.com/vxunderground) - go check it out for a deep dive on all the subtleties involved in this process, that will not be covered in these notes.

For the sake of this lab, we are going to turn a simple C program \(that is provided by [hasherezade](https://twitter.com/hasherezade) in the aforementioned paper\) that pops a message box, to shellcode and execute it by manually injecting it into an RWX memory location inside notepad.

{% hint style="info" %}
Code samples used throughout this lab are written by [hasherezade](https://twitter.com/hasherezade), unless stated otherwise.
{% endhint %}

## Overview

Below is a quick overview of how writing and compiling shellcode in C works:

1. Shellcode is written in C
2. C code is compiled to a list of assembly instructions
3. Assembly instructions are cleaned up and external dependencies removed
4. Assembly is linked to a binary
5. Shellcode is extracted from the binary
6. This shellcode can now be injected/executed by leveraging [code injection techniques](./)

## Walkthrough

{% hint style="info" %}
1. This lab is based on Visual Studio 2019 Community Edition. 
2. Program and shellcode in this lab targets x64 architecture.
{% endhint %}

### 1. Preparing Dev Environment

First of, let's start the Developer Command Prompt for VS 2019, which will set up our dev environment required for compiling and linking the C code used in this lab:

![](../../.gitbook/assets/image%20%28717%29.png)

In my case, the said console is located here:

```text
C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat
```

Let's start it like so:

```text
cmd /k "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat"
```

![](../../.gitbook/assets/image%20%28623%29.png)

### 2. Generating Assembly Listing

Below are two C files that make up the program we will be converting to shellcode:

* `c-shellcode.cpp` - the program that pops a message box
* `peb-lookup.h` - header file required by the `c-shellcode.cpp`, which contains functions for resolving addresses for `LoadLibraryA` and `GetProcAddress`

{% tabs %}
{% tab title="c-shellcode.cpp" %}
```cpp
#include <Windows.h>
#include "peb-lookup.h"

// It's worth noting that strings can be defined nside the .text section:
#pragma code_seg(".text")

__declspec(allocate(".text"))
wchar_t kernel32_str[] = L"kernel32.dll";

__declspec(allocate(".text"))
char load_lib_str[] = "LoadLibraryA";

int main()
{
    // Stack based strings for libraries and functions the shellcode needs
    wchar_t kernel32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
    char load_lib_name[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
    char get_proc_name[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s', 0 };
    char user32_dll_name[] = { 'u','s','e','r','3','2','.','d','l','l', 0 };
    char message_box_name[] = { 'M','e','s','s','a','g','e','B','o','x','W', 0 };

    // stack based strings to be passed to the messagebox win api
    wchar_t msg_content[] = { 'H','e','l','l','o', ' ', 'W','o','r','l','d','!', 0 };
    wchar_t msg_title[] = { 'D','e','m','o','!', 0 };

    // resolve kernel32 image base
    LPVOID base = get_module_by_name((const LPWSTR)kernel32_dll_name);
    if (!base) {
        return 1;
    }

    // resolve loadlibraryA() address
    LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)load_lib_name);
    if (!load_lib) {
        return 2;
    }

    // resolve getprocaddress() address
    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)get_proc_name);
    if (!get_proc) {
        return 3;
    }

    // loadlibrarya and getprocaddress function definitions
    HMODULE(WINAPI * _LoadLibraryA)(LPCSTR lpLibFileName) = (HMODULE(WINAPI*)(LPCSTR))load_lib;
    FARPROC(WINAPI * _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName)
        = (FARPROC(WINAPI*)(HMODULE, LPCSTR)) get_proc;

    // load user32.dll
    LPVOID u32_dll = _LoadLibraryA(user32_dll_name);

    // messageboxw function definition
    int (WINAPI * _MessageBoxW)(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCWSTR lpText,
        _In_opt_ LPCWSTR lpCaption,
        _In_ UINT uType) = (int (WINAPI*)(
            _In_opt_ HWND,
            _In_opt_ LPCWSTR,
            _In_opt_ LPCWSTR,
            _In_ UINT)) _GetProcAddress((HMODULE)u32_dll, message_box_name);

    if (_MessageBoxW == NULL) return 4;


    // invoke the message box winapi
    _MessageBoxW(0, msg_content, msg_title, MB_OK);

    return 0;
}
```
{% endtab %}

{% tab title="peb-lookup.h" %}
```cpp
#pragma once
#include <Windows.h>

#ifndef __NTDLL_H__

#ifndef TO_LOWERCASE
#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1)
#endif


typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;

} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID      EntryInProgress;

} PEB_LDR_DATA, * PPEB_LDR_DATA;

//here we don't want to use any functions imported form extenal modules

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
    void* BaseAddress;
    void* EntryPoint;
    ULONG   SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG   Flags;
    SHORT   LoadCount;
    SHORT   TlsIndex;
    HANDLE  SectionHandle;
    ULONG   CheckSum;
    ULONG   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;

    // [...] this is a fragment, more elements follow here

} PEB, * PPEB;

#endif //__NTDLL_H__

inline LPVOID get_module_by_name(WCHAR* module_name)
{
    PPEB peb = NULL;
#if defined(_WIN64)
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY list = ldr->InLoadOrderModuleList;

    PLDR_DATA_TABLE_ENTRY Flink = *((PLDR_DATA_TABLE_ENTRY*)(&list));
    PLDR_DATA_TABLE_ENTRY curr_module = Flink;

    while (curr_module != NULL && curr_module->BaseAddress != NULL) {
        if (curr_module->BaseDllName.Buffer == NULL) continue;
        WCHAR* curr_name = curr_module->BaseDllName.Buffer;

        size_t i = 0;
        for (i = 0; module_name[i] != 0 && curr_name[i] != 0; i++) {
            WCHAR c1, c2;
            TO_LOWERCASE(c1, module_name[i]);
            TO_LOWERCASE(c2, curr_name[i]);
            if (c1 != c2) break;
        }
        if (module_name[i] == 0 && curr_name[i] == 0) {
            //found
            return curr_module->BaseAddress;
        }
        // not found, try next:
        curr_module = (PLDR_DATA_TABLE_ENTRY)curr_module->InLoadOrderModuleList.Flink;
    }
    return NULL;
}

inline LPVOID get_func_by_name(LPVOID module, char* func_name)
{
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* exportsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (exportsDir->VirtualAddress == NULL) {
        return NULL;
    }

    DWORD expAddr = exportsDir->VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)module);
    SIZE_T namesCount = exp->NumberOfNames;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    //go through names:
    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*)module + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)module + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)module + (*nameIndex) * sizeof(DWORD));

        LPSTR curr_name = (LPSTR)(*nameRVA + (BYTE*)module);
        size_t k = 0;
        for (k = 0; func_name[k] != 0 && curr_name[k] != 0; k++) {
            if (func_name[k] != curr_name[k]) break;
        }
        if (func_name[k] == 0 && curr_name[k] == 0) {
            //found
            return (BYTE*)module + (*funcRVA);
        }
    }
    return NULL;
}
```
{% endtab %}
{% endtabs %}

We can now convert the C code in `c-shellcode.cpp` to assembly instructions like so:

```text
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.26.28801\bin\Hostx64\x64\cl.exe" /c /FA /GS- c-shellcode.cpp
```

The switches' instruct the compiler to:

* `/c` - Prevent the automatic call to LINK
* `/FA` - Create a listing file containing assembler code for the provided C code
* `/GS-` - Turn off detection of some buffer overruns

Below shows how we compile the `c-shellcode.cpp` into `c-shellcode.asm`:

![Assembly instructions are generated based on the c-shellcode.asm](../../.gitbook/assets/image%20%28652%29.png)

### 3. Massaging Assembly Listing

Now that our C code has been convered to assembly in `c-shellcode.asm`, we need to clean up the file a bit, so we can link it to an .exe without errors and to avoid the shellcode from crashing. Specifically, we need to:

1. Remove dependencies from external libraries
2. Align stack
3. Fix a simple syntax issue

#### 3.1 Remove Exteranal Libraries

First off, we need to comment out or remove instructions to link this module with libraries `libcmt` and `oldnames`:

![Comment out both includelib directives](../../.gitbook/assets/image%20%28547%29.png)

#### 3.2 Fix Stack Alignment

Add procedure `AlignRSP` right at the top of the first `_TEXT` segment in our `c-shellcode.asm`:

```css
; https://github.com/mattifestation/PIC_Bindshell/blob/master/PIC_Bindshell/AdjustStack.asm

; AlignRSP is a simple call stub that ensures that the stack is 16-byte aligned prior
; to calling the entry point of the payload. This is necessary because 64-bit functions
; in Windows assume that they were called with 16-byte stack alignment. When amd64
; shellcode is executed, you can't be assured that you stack is 16-byte aligned. For example,
; if your shellcode lands with 8-byte stack alignment, any call to a Win32 function will likely
; crash upon calling any ASM instruction that utilizes XMM registers (which require 16-byte)
; alignment.

AlignRSP PROC
    push rsi ; Preserve RSI since we're stomping on it
    mov rsi, rsp ; Save the value of RSP so it can be restored
    and rsp, 0FFFFFFFFFFFFFFF0h ; Align RSP to 16 bytes
    sub rsp, 020h ; Allocate homing space for ExecutePayload
    call main ; Call the entry point of the payload
    mov rsp, rsi ; Restore the original value of RSP
    pop rsi ; Restore RSI
    ret ; Return to caller
AlignRSP ENDP
```

Below shows how it should look like in the `c-shellcode.asm`:

![Add AlignRSP at the top of \_TEXT segment](../../.gitbook/assets/image%20%28742%29.png)

#### 3.3 Remove PDATA and XDATA Segments

Remove or comment out `PDATA` and `XDATA` segments as shown below:

![](../../.gitbook/assets/image%20%28636%29.png)

#### 3.4 Fix Syntax Issues

We need to change line `mov rax, QWORD PTR gs:96` to `mov rax, QWORD PTR gs:[96]`: 

![](../../.gitbook/assets/image%20%28713%29.png)

### 4. Linking to an EXE

We are now ready to link the assembly listings inside `c-shellcode.asm` to get an executable `c-shellcode.exe`:

```text
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.26.28801\bin\Hostx64\x64\ml64.exe" c-shellcode.asm /link /entry:AlignRSP
```

![](../../.gitbook/assets/image%20%28570%29.png)

### 5. Testing the EXE

We can now check that if `c-shellcode.exe` does what it was meant to - pops a message box:

![](../../.gitbook/assets/image%20%28735%29.png)

### 6. Copying Out Shellcode

Once we have the `c-shellcode.exe` binary, we can extract the shellcode and execute it using any [code injection](./) technique, but for the sake of this lab, we will copy it out as a list of hex values and simply paste them into an RWX memory slot inside a notepad.exe.

Let's copy out the shellcode from the `.text` section, which in our case starts at 0x200 into the raw file:

![](../../.gitbook/assets/image%20%28612%29.png)

If you are wondering how we found the shellcode location, look at the `.text` section - you can extract  if from there too:

![](../../.gitbook/assets/image%20%28662%29.png)

### 7. Testing Shellcode

Once the shellcode is copied, let's paste it to an RWX memory area \(you can set any memory location to have permissions RWX with xdbg64\) inside notepad, set RIP to that location and resume code execution in that location. If we did all the previous steps correctly, we should see our shellcode execute and pop the message box:

![notepad.exe executing shellcode that pops a MessageBox as seen in xdbg64](../../.gitbook/assets/pasting-executing-shellcode%20%281%29.gif)

## References

[From a C project, through assembly, to shellcode](https://vxug.fakedoma.in/papers/VXUG/Exclusive/FromaCprojectthroughassemblytoshellcodeHasherezade.pdf)

