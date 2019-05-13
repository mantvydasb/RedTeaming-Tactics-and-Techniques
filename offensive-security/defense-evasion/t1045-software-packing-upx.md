---
description: 'Defense Evasion, Code Obfuscation'
---

# T1045: Packed Binaries

For this exercise, I will pack a binary with a well known UPX packer.

## Execution

```csharp
.\upx.exe -9 -o .\nc-packed.exe .\nc.exe
```

![](../../.gitbook/assets/upx-pack.png)

Note how the file size shrank by 50%!

## Observations

Some of the tell-tale signs of a UPX packed binary are the PE section headers - note the differences between `nc-packed.exe` and `nc.exe`:

![](../../.gitbook/assets/upx-packed-vs-unpacked.png)

Another important observation should be made from the above screenshot - `nc-packed` binary's `Raw Size` \(section's size on the disk\) is 0 bytes for the UPX0 section \(.text/.code section\) and therefore much smaller than the `Virtual Size` \(space allocated for this section in the process memory\), whereas these values in a non-packed binary are of similar sizes.  This is another good indicator suggesting the binary may be packed.

Yet another sign of a potentially packed binary is a low\(-er\) number of imported DLLs and their functions:

![](../../.gitbook/assets/upx-imports.png)

Note how the packed binary only imports one function from the `WSOCK32.dll` and many more are imported by a non-packed binary:

![](../../.gitbook/assets/upx-sockets.png)

Another classic sign of a packed binary is `KERNEL32.dll` **only** importing a couple of functions, including:`LoadLibraryA` and `GetProcAddress`. These are crucial for the binary as they are used to locate other important functions of the `KERNEL32.dll` located in the process memory, hence packed binaries will almost always have those functions exposed since they are required for the binary to work properly:

![](../../.gitbook/assets/upx-kernel.png)

If you have no fancy malware analysis tools to hand, but you have `strings.exe`, you can make a fairly good educated guess whether the binary is packed by just running strings against it and noting the DLL imports - if there's only a few of them \(and more importantly - GetProcAddress and LoadLibrary\) and they are from KERNEL32.dll - the binary is likely packed:

![](../../.gitbook/assets/upx-strings.png)

## References

{% embed url="https://attack.mitre.org/wiki/Technique/T1045" %}

