---
description: Defense Evasion
---

# T1202: Forfiles Indirect Command Execution

This technique launches an executable without a cmd.exe.

## Execution

```csharp
forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe
```

![](../../.gitbook/assets/forfiles-executed.png)

## Observations

Defenders can monitor for process creation/commandline logs to detect this activity:

![](../../.gitbook/assets/forfiles-ancestry.png)

![](../../.gitbook/assets/forfiles-cmdline.png)

## References

{% embed url="https://attack.mitre.org/wiki/Technique/T1202" %}

