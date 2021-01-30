# Listing Open Handles and Finding Kernel Object Addresses

It's possible to enumerate all open handles \(processes, files, mutexes, keys, sections, etc\) on a system \(no admin rights required\), which means it is possible to get a virtual address of any kernel object \(for example `EPROCESS` for a process object\) in the kernel space from user space.

Being able to locate a virtual address of a kernel object \(like `EPROCESS`\) is useful in kernel exploitation. For example, if you compromise a machine and discover there is a vulnerable driver, through which you  can read/write kernel memory from userland, you could exploit it for privilege escalation by locating a kernel object `EPROCESS` of a privileged process, for example `winlogon.exe`, stealing its security token and applying it to your low privileged `cmd.exe` process to gain a shell with `SYSTEM` privileges.

A list of all the open handles on the system is retrieved by using a `NtQuerySystemInformation` API and a couple of undocumented, but well known structures `SYSTEM_HANDLE_INFORMATION` and `SYSTEM_HANDLE_TABLE_ENTRY_INFO`.

## Code

Below code retrieves all handles opened by the `SYSTEM` process \(PID 4\):

{% hint style="danger" %}
* Below code does not handle errors
* `SystemHandleInformationSize` is a hardcoded value, which you should not do in production code. Instead, you should:
  * start with an arbitrary size for `SystemHandleInformationSize`
  * call `NtQuerySystemInformation` in a loop, until it no longer returns `0xc0000004` \(`STATUS_INFO_LENGTH_MISMATCH`\)
  * if `0xc0000004` is returned, increase `SystemHandleInformationSize`
{% endhint %}

```cpp
#include <iostream>
#include <Windows.h>
#include <winternl.h>

#define SystemHandleInformation 0x10
#define SystemHandleInformationSize 1024 * 1024 * 2

using fNtQuerySystemInformation = NTSTATUS(WINAPI*)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// handle information
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

// handle table information
typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;


int main()
{
    ULONG returnLenght = 0;
    fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");
    PSYSTEM_HANDLE_INFORMATION handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SystemHandleInformationSize);
    NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, SystemHandleInformationSize, &returnLenght);

    for (int i = 0; i < handleTableInformation->NumberOfHandles; i++)
    {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)handleTableInformation->Handles[i];

        if (handleInfo.UniqueProcessId == 4)
        {
            printf_s("Handle 0x%x at 0x%p, PID: %x\n", handleInfo.HandleValue, handleInfo.Object, handleInfo.UniqueProcessId);
        }
        else 
        {
            break;
        }
    }

    return 0;
}
```

{% hint style="info" %}
**Remember**  
The above code could be easily modified to find an object's location in kernel given its handle.
{% endhint %}

## Validation

Let's see if the code above lists out the handles and the object addresses those handles point to in the kernel memory correctly.

If we compile and run the code, we will get a list of all the handles for the process with PID 4:

![](../../.gitbook/assets/image%20%28721%29.png)

We can cross-check and ensure that our listed handles are accurate with Process Hacker by inspecting the `Handles` tab of the `SYSTEM` process \(PID 4\). Let's check the first handle 0x4:

![](../../.gitbook/assets/image%20%28690%29.png)

The above shows:

* in green - handle id \(0x4\)
* in blue - process id \(4\) of the process which has the handle 0x4 opened \(SYSTEM process has a handle to itself\)
* in red - object's \(pointed to by the handle\) location in kernel memory \(`0xffff87077c882300`\)

We can easily check the object at `0xffff8f077c882300` in WinDBG:

```text
!object 0xffff8f077c882300
```

The above command indicates that `0xffff8f077c882300` is a valid object address and it's of type Process:

![Output of !object 0xffff8f077c882300](../../.gitbook/assets/image%20%28639%29.png)

We can confirm `0xffff8f077c882300` is a process object by using a `!process` command in WinDBG:

```text
!process 0xffff8f077c882300 0
```

Below confirms that it's indeed a process object:

* in red - process object location in kernel memory \(0xffff8f077c882300\)
* in blue - process id \(4\)
* in lime - process name \(system\)

![Output of !process 0xffff8f077c882300 0](../../.gitbook/assets/image%20%28591%29.png)

Finally, we can overlay the `_EPROCESS` over `ffff8f077c882300` and print the `UniqueProcessId` and `ImageFileNames`, that again confirm it's a `SYSTEM` process with PID 4:

```text
dt _eprocess ffff8f077c882300 uniqueprocessid imagefilename
```

![](../../.gitbook/assets/image%20%28608%29.png)

## References

{% embed url="https://processhacker.sourceforge.io/doc/struct\_\_\_s\_y\_s\_t\_e\_m\_\_\_h\_a\_n\_d\_l\_e\_\_\_i\_n\_f\_o\_r\_m\_a\_t\_i\_o\_n.html" %}

{% embed url="https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle.htm" %}

{% embed url="https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle\_table\_entry.htm?ts=0,81" %}

{% embed url="https://blez.wordpress.com/2012/09/17/enumerating-opened-handles-from-a-process/" %}

