# Import Adress Table \(IAT\) Hooking

## Overview

* Windows portable executable contains a structure called `Import Address Table (IAT)` 
* IAT contains pointers to information that is critical for an executable to do its job: 
  * a list of DLLs it depends on for providing the expected functionality
  * a list of function names and their addresses from those DLLs that may be called by the binary at some point
* It is possible to hook function pointers specified in the IAT by overwriting the target function's address with a rogue function address and optionally to execute the originally intended function

Below is a simplified diagram that attempts to visualize the flow of events before and after a function   
\(`MessageBoxA` in this example, but could be any\) is hooked:

![](../../.gitbook/assets/image%20%28107%29.png)

**Before hooking**

1. the target program calls a WinAPI `MessageBoxA` function
2. the program looks up the `MessageBoxA` address in the IAT 
3. code execution jumps to the  `kernel32!MessageBoxA` address resolved in step 2 where legitimate code for displaying the `MessageBoxA` \(green box\) lives

**After hooking**

1. the target program calls `MessageBoxA` like before hooking
2. the program looks up the `MessageBoxA` address in the IAT 
3. this time, because the IAT has been tampered with, the `MessageBoxA` address in the IAT is pointing to a rogue `hookedMessageBox` function \(red box\) 
4. the program jumps to the `hookedMessageBox` retrieved in step 3
5. `hookedMessageBox` intercepts the `MessageBoxA` parameters and executes some malicous code 
6. `hookedMessageBox` calls the legitimate `kernel32!MessageBoxA` routine

## Walkthrough

In this lab I'm going to write a simple executable that will hook `MessageBoxA` in its process memory space by leveraging the IAT hooking technique and redirect it to a function called `hookedMessageBox` as per above visualisation and then transfer the code execution back to the intended `MessageBoxA` routine.

{% hint style="warning" %}
IAT hooking is usually performed by a DLL injected into a target process, but for the sake of simplicity and illustration, in this lab, the IAT hooking is implemented in the local process.
{% endhint %}

To hook the `MessageBoxA` we need to:

1. Save memory address of the original `MessageBoxA`
2. Define a `MessageBoxA` function prototype
3. Create a `hookedMessageBox` \(rogue `MessageBoxA`\) function with the above prototype. This is the function that intercepts the original `MessageBoxA` call, executes some malicious code \(in my case, it invokes a `MessageBoxW`\) and transfers code execution to the original `MessageBoxA` routine for which the address is retrieved in step 1
4. Parse IAT table until address of `MessageBoxA` is found
   1. More about PE parsing in [Parsing PE File Headers with C++](../../miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++.md)
   2. More about Import Address Table parsing in [Reflective DLL Injection](reflective-dll-injection.md#resolving-import-address-table)
5. Replace `MessageBoxA` address with address of the `hookedMessageBox`

As a reminder, we can check the IAT of any binary using CFF Explorer or any other PE parser. Below highlighted is one of the IAT entries - the target function `MessageBoxA` that will be patched during runtime and swapped with `hookedMessageBox`:

![IAT table, CFF Explorer](../../.gitbook/assets/image%20%28306%29.png)

## Code

Below is the code and key comments showing how IAT hooking could be implemented:

```cpp
#include <iostream>
#include <Windows.h>
#include <winternl.h>

// define MessageBoxA prototype
using PrototypeMessageBox = int (WINAPI *)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

// remember memory address of the original MessageBoxA routine
PrototypeMessageBox originalMsgBox = MessageBoxA;

// hooked function with malicious code that eventually calls the original MessageBoxA
int hookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	MessageBoxW(NULL, L"Ola Hooked from a Rogue Senor .o.", L"Ola Senor o/", 0);
	// execute the original NessageBoxA
	return originalMsgBox(hWnd, lpText, lpCaption, uType);
}

int main()
{
	// message box before IAT unhooking
	MessageBoxA(NULL, "Hello Before Hooking", "Hello Before Hooking", 0);
	
	LPVOID imageBase = GetModuleHandleA(NULL);
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);
	LPCSTR libraryName = NULL;
	HMODULE library = NULL;
	PIMAGE_IMPORT_BY_NAME functionName = NULL; 

	while (importDescriptor->Name != NULL)
	{
		libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)imageBase;
		library = LoadLibraryA(libraryName);

		if (library)
		{
			PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
			originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
			firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);

			while (originalFirstThunk->u1.AddressOfData != NULL)
			{
				functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData);
					
				// find MessageBoxA address
				if (std::string(functionName->Name).compare("MessageBoxA") == 0)
				{
					SIZE_T bytesWritten = 0;
					DWORD oldProtect = 0;
					VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);
						
					// swap MessageBoxA address with address of hookedMessageBox
					firstThunk->u1.Function = (DWORD_PTR)hookedMessageBox;
				}
				++originalFirstThunk;
				++firstThunk;
			}
		}

		importDescriptor++;
	}

	// message box after IAT hooking
	MessageBoxA(NULL, "Hello after Hooking", "Hello after Hooking", 0);
	
	return 0;
}
```

## Demo

Our binary's base address \(ImageBase\) in memory is at `0x00007FF69C010000`:

![](../../.gitbook/assets/image%20%28411%29.png)

Before IAT manipulation, `MessageBoxA` points to `0x00007ffe78071d30`:

![Line 58 in provided code - MessageBoxA is located at 0x00007ffe78071d30 before hooking ](../../.gitbook/assets/image%20%28131%29.png)

If interested, we can manually work out that `MessageBoxA` is located at `0x00007ffe78071d30` by:

1. adding the ImageBase `0x00007FF69C010000` and Relative Virtual Address \(RVA\) of the First Thunk of `MessageBoxA` `0x000271d0` which equals to `0x00007FF69C0371D0`
2. dereferrencing `0x00007FF69C0371D0`

![RVA of the function MessageBoxA](../../.gitbook/assets/image%20%28154%29.png)

Dereferrencing `0x00007FF69C0371D0 (0x00007FF69C010000 + 0x000271d0)` reveals the `MessageBoxA` location in memory `0x00007ffe78071d30`:

![0x00007FF69C0371D0 points to MessageBoxA at 0x00007ffe78071d30 ](../../.gitbook/assets/image%20%28395%29.png)

Now, our `hookedMessageBox` is located at `0x00007ff396d5440`:

![](../../.gitbook/assets/image%20%28228%29.png)

After the IAT manipulation code executes, `MessageBoxA` points to `hookedMessageBox` at `0x00007ff396d5440`

![](../../.gitbook/assets/image%20%28402%29.png)

Once the function pointers are swapped, we can see that calling the `MessageBoxA` with an argument `Hello after Hooking` does not print `Hello after Hooking`, rather, the message text is that seen in the `hookedMessageBox` routine, confirming that the IAT hook was successful and the rouge function was called first:

![](../../.gitbook/assets/image%20%28230%29.png)

Below shows the entire flow of key events that happen in this program:

1. Before hooking, `MessageBoxA` is called with an argument `Hello Before Hooking` and the program displays the message as expected
2. After IAT hooking, `MessageBoxA` is called with an argument `Hello after Hooking`, but the program gets redirected to a `hookedMessageBox` function and displays `Ola Hooked from a Rogue Senor .o.`
3. Finally, `hookedMessageBox` calls the original `MessageBoxA` which prints out the intended `Hello after Hooking`

![](../../.gitbook/assets/iat-hook-demo.gif)

## References

{% page-ref page="../../miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++.md" %}

{% page-ref page="reflective-dll-injection.md" %}

{% page-ref page="how-to-hook-windows-api-using-c++.md" %}

