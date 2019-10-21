# Executing Code in Control Panel Item through an Exported Cplapplet Function

This is a quick note that shows how to execute code in a .cpl file, which is a regular DLL file representing a Control Panel item.

The .cpl file needs to export one function called CplApplet in order to be recognized by Windows as a Control Panel item.

## Code

```cpp
// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <Windows.h>

//Cplapplet
extern "C" __declspec(dllexport) LONG Cplapplet(
	HWND hwndCpl,
	UINT msg,
	LPARAM lParam1,
	LPARAM lParam2
)
{
	MessageBoxA(NULL, "Hey there, I am now your control panel item you know.", "Control Panel", 0);
	return 1;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		Cplapplet(NULL, NULL, NULL, NULL);
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

Once the CPL is compiled, we can see our exported function `Cplapplet`:

![](../../.gitbook/assets/image%20%2844%29.png)

## Demo

![](../../.gitbook/assets/cplexecution.gif)

## References

{% embed url="https://github.com/fireeye/DueDLLigence/blob/master/DueDLLigence/DueDLLigence.cs" %}

{% embed url="https://docs.microsoft.com/en-us/windows/win32/shell/using-cplapplet" %}

