---
description: >-
  Unload sysmon driver which causes the system to stop recording sysmon event
  logs.
---

# Unloading Sysmon Driver

## Execution

{% code title="attacker@victim" %}
```text
fltMC.exe unload SysmonDrv
```
{% endcode %}

![](../../.gitbook/assets/sysmon-cmd.png)

## Observations

Windows event logs suggesting `SysmonDrv` was unloaded successfully:

![](../../.gitbook/assets/sysmon-unload-log1.png)

As well as processes requesting special privileges:

![](../../.gitbook/assets/sysmon-unload-log2.png)

Note how in the last 35 minutes since the driver was unloaded, no further process creation events were recorded, although I spawned new processes during that time:

![](../../.gitbook/assets/sysmon-last-event.png)

Note how the system thinks that the sysmon is still running, which it is, but not doing anything useful:

![](../../.gitbook/assets/sysmon-running.png)

## References

{% embed url="https://twitter.com/Moti\_B/status/1019307375847723008" %}

