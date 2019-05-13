---
description: Loading DLL from memory rather than disk.
---

# Reflective DLL Injection

This is a DLL injection technique that allows an attacker to inject a DLL's into a remote \(victim\) process **from memory** rather than a disk - a stealthier way to execute malicious code.

The way the reflective injection works is nicely described by Stephen Fewer [here](https://github.com/stephenfewer/ReflectiveDLLInjection):

> * Execution is passed, either via CreateRemoteThread\(\) or a tiny bootstrap shellcode, to the library's ReflectiveLoader function which is an exported function found in the library's export table.
> * As the library's image will currently exists in an arbitrary location in memory the ReflectiveLoader will first calculate its own image's current location in memory so as to be able to parse its own headers for use later on.
> * The ReflectiveLoader will then parse the host processes kernel32.dll export table in order to calculate the addresses of three functions required by the loader, namely LoadLibraryA, GetProcAddress and VirtualAlloc.
> * The ReflectiveLoader will now allocate a continuous region of memory into which it will proceed to load its own image. The location is not important as the loader will correctly relocate the image later on.
> * The library's headers and sections are loaded into their new locations in memory.
> * The ReflectiveLoader will then process the newly loaded copy of its image's import table, loading any additional library's and resolving their respective imported function addresses.
> * The ReflectiveLoader will then process the newly loaded copy of its image's relocation table.
> * The ReflectiveLoader will then call its newly loaded image's entry point function, DllMain with DLL\_PROCESS\_ATTACH. The library has now been successfully loaded into memory.
> * Finally the ReflectiveLoader will return execution to the initial bootstrap shellcode which called it, or if it was called via CreateRemoteThread, the thread will terminate.

## Execution

This lab assumes that the attacker has already gained a meterpreter shell from the victim system and will now attempt to perform a reflective DLL injection into a remote process on a compromised victim system, more specifically into a `notepad.exe` process with PID `6156`

Metasploit's post-exploitation module `windows/manage/reflective_dll_inject` configured:

![](../../.gitbook/assets/reflective-dll-options%20%281%29.png)

{% hint style="info" %}
`Reflective_dll.x64.dll` is the DLL compiled from Steven Fewer's [reflective dll injection](%20https://github.com/stephenfewer/ReflectiveDLLInjection) project on github.
{% endhint %}

After executing the post exploitation module, the below graphic shows how the notepad.exe executes the malicious payload that came from a reflective DLL that was sent over the wire from the attacker's system:

![](../../.gitbook/assets/reflective-dll-gif.gif)

## Observations

Once the metasploit's post-exploitation module is run, the procmon accurately registers that notepad created a new thread:

![](../../.gitbook/assets/reflective-dll-injection-new-thread.png)

Let's see if we can locate where the contents of `reflective_dll.x64.dll` are injected into the victim process when the metasploit's post-exploitation module executes.

For that, lets debug notepad in WinDBG and set up a breakpoint for `MessageBoxA` as shown below and run the post-exploitation module again:

```cpp
0:007> bp MessageBoxA
0:007> bl
0 e 00000000`77331304     0001 (0001)  0:**** USER32!MessageBoxA
```

The breakpoint is hit:

![](../../.gitbook/assets/reflective-dll-bp-hit.png)

At this point, we can inspect the stack with `kv` and see the call trace. A couple of points to note here:

* return address the code will jump to after the `USER32!MessageBoxA` finishes is `00000000031e103e`
* inspecting assembly instructions around `00000000031e103e`, we see a call instruction `call qword ptr [00000000031e9208]`
* inspecting bytes stored in `00000000031e9208`, \(`dd 00000000031e9208 L1`\) we can see they look like a memory address `0000000077331304` \(note this address\)
* inspecting the EIP pointer \(`r eip`\) where the code execution is paused at the moment, we see that it is the same `0000000077331304` address, which means that the earlier mentioned instruction `call qword ptr [00000000031e9208]` is the actual call to `USER32!MessageBoxA`
* This means that prior to the above mentioned instruction, there must be references to the variables that are passed to the `MessageBoxA` function:

![](../../.gitbook/assets/reflective-dll-injection-mem-analysis.png)

If we inspect the `00000000031e103e` 0x30 bytes earlier, we can see some suspect memory addresses and the call instruction almost immediatley after that:

![](../../.gitbook/assets/reflective-dll-injection-variables.png)

Upon inspecting those two addresses - they are indeed holding the values the `MessageBoxA` prints out upon successful DLL injection into the victim process:

```cpp
0:007> da 00000000`031e92c8
00000000`031e92c8  "Reflective Dll Injection"
0:007> da 00000000`031e92e8
00000000`031e92e8  "Hello from DllMain!"
```

![](../../.gitbook/assets/reflective-dll-injection-strings.png)

Looking at the output of the `!address` function and correlating it with the addresses the variables are stored at, it can be derived that the memory region allocated for the evil dll is located in the range `031e0000 - 031f7000`:

![](../../.gitbook/assets/reflective-dll-injection-range.png)

Indeed, if we look at the `031e0000`, we can see the executable header \(MZ\) and the strings fed into the `MessageBoxA` API can be also found further into the binary:

![](../../.gitbook/assets/reflective-dll-strings.gif)

## Detecting Reflective DLL Injection with Volatility

`Malfind` is the Volatility's pluging responsible for finding various types of code injection and reflective DLL injection can usually be detected with the help of this plugin. 

The plugin, at a high level will scan through various memory regions described by Virtual Address Descriptors \(VADs\) and look for any regions with `PAGE_EXECUTE_READWRITE` memory protection and then check for the magic bytes `4d5a` \(MZ in ASCII\) at the very beginning of those regions as those bytes signify the start of a Windows executable \(i.e exe, dll\):

```csharp
volatility -f /mnt/memdumps/w7-reflective-dll.bin malfind --profile Win7SP1x64
```

Note how in our case, volatility discovered the reflective dll injection we inspected manually above with WindDBG:

![](../../.gitbook/assets/reflective-dll-volatility.png)

## References

{% embed url="https://github.com/stephenfewer/ReflectiveDLLInjection" %}

{% embed url="https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Mal" %}

