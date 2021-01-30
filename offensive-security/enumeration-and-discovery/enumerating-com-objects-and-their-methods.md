# Enumerating COM Objects and their Methods

This is a quick note to capture some of the commands for finding interesting COM objects and the methods they expose, based on the great [article](https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html) from Fireeye.

> The Microsoft Component Object Model \(COM\) is a platform-independent, distributed, object-oriented system for creating binary software components that can interact
>
> [https://docs.microsoft.com/en-us/windows/win32/com/the-component-object-model](https://docs.microsoft.com/en-us/windows/win32/com/the-component-object-model)

This is less of a post-exploitation technique, rather a method that allows one to look for interesting COM objects, that could be leveraged by one's malware.

## Enumerating COM Objects

We can find all the COM objects registered on the Windows system with:

```csharp
gwmi Win32_COMSetting | ? {$_.progid } | sort | ft ProgId,Caption,InprocServer32
```

![](../../.gitbook/assets/image%20%28633%29.png)

## Enumerating COM Object Methods

Once we have the list of COM objects and have identified an interesting COM object, we can now check the methods it exposes. In our case, let's pick a COM object `WScript.Shell.1` and check its methods like so:

```csharp
$o = [activator]::CreateInstance([type]::GetTypeFromProgID(("WScript.Shell.1"))) | gm
```

Below are the methods exposed by `WScript.Shell.1` COM object, one of which is `RegRead`:

![](../../.gitbook/assets/image%20%28716%29.png)

Let's see if we can read a registry value with `RedRead` method exposed by the `WScript.Shell.1`. `RedRead` accepts one string as an argument - a path to the registry value:

```csharp
$o.RegRead("HKEY_CURRENT_USER\Volatile Environment\LOGONSERVER")
```

Below shows how a registry value was read successfully:

![](../../.gitbook/assets/image%20%28546%29.png)

## Exposing All COM Object Methods

We can iterate through all the COM objects and list their methods and save it all to a text file that we can later on inspect for any other interesting methods:

```csharp
$com = gwmi Win32_COMSetting | ? {$_.progid } | select ProgId,Caption,InprocServer32

$com | % {
    $_.progid | out-file -append methods.txt
    [activator]::CreateInstance([type]::GetTypeFromProgID(($_.progid))) | gm | out-file -append methods.txt
    "`n`n" | out-file -append methods.txt
}
```

Below shows the output file with all the methods of all COM objects exposed, in focus are the methods for `Shell.Application.1` COM object:

![](../../.gitbook/assets/image%20%28738%29.png)

## References

{% embed url="https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html" %}

