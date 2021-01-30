# Lateral Movement via DLL Hijacking

This is a quick write-up that outlines how it's possible to leverage DLL hijacking for lateral movement as described by [@domchell](https://twitter.com/domchell) in [I Like to Move It: Windows Lateral Movement Part 3: DLL Hijacking](https://www.mdsec.co.uk/2020/10/i-live-to-move-it-windows-lateral-movement-part-3-dll-hijacking/)

## 1. Find a DLL to Hijack

Fire up some Windows VM and inspect it with ProcMon to find any DLLs that could be hijacked. Usually there's many opportunities on any given Windows host. To find some target DLLs, fire launch procmon, set filters to `path ends with .dll && result is NAME NOT FOUND` and you will see something like this:

![](../../.gitbook/assets/image%20%28741%29.png)

In these notes, we will be targeting the missing DLL located at:

```text
c:\windows\system32\sharedres.dll
```

{% hint style="info" %}
There may be better processes with missing DLLs to target, for example, those that you can force to attempt to load the DLL that is missing and you are about to hijack.
{% endhint %}

## 2. Create Payload DLL

Now, you need to create a DLL that contains your payload - i.e. Cobalt Strike beacon. This is the DLL you will plant on the target system in `c:\windows\system32\sharedres.dll`, because it's missing and svchost.exe is trying to load it. 

In this situation, it is strongly advised to ensure that your malicious DLL to not only executes your payload, but also exports the same functions the DLL you are hijacking exports, so find the real DLL on your system or on the internet to check what exports it contains and make sure your DLL has those exports. Afteral, the process that will load your DLL is loading it for a reason - it will want to use some functions that that DLL and will crash if it does not find them.

{% hint style="danger" %}
It is strongly advised to ensure that your malicious DLL exports the same functions as the DLL you are hijacking, otherwise you may crash the process or compromise the system's stability.
{% endhint %}

See my lab on [DLL proxying](../persistence/dll-proxying-for-persistence.md) and check out a tool [Koppeling](https://github.com/monoxgas/Koppeling) by [@monoxgas](https://twitter.com/monoxgas?lang=en) that automates DLL proxying and more.

## 3. Copy Payload DLL

Once you have your malicious DLL ready, you can now hijack the missing DLL on the target system by copying your DLL over to the remote machine via, say SMB:

```text
copy payload.dll \\target-pc\c$\windows\system32\sharedres.dll
```

## 4. Wait & Profit

At this point, you just wait for the svchost.exe to attempt to load the `c:\windows\system32\sharedres.dll`. When that happens, your payload will be executed.

## Detection

For detection ideas, check out the link in the references.

## References

{% embed url="https://www.mdsec.co.uk/2020/10/i-live-to-move-it-windows-lateral-movement-part-3-dll-hijacking/" %}

