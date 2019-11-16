---
description: 'Code execution, privilege escalation, lateral movement and persitence.'
---

# T1053: Schtask

## Execution

Creating a new scheduled task that will launch shell.cmd every minute:

{% code title="attacker@victim" %}
```bash
schtasks /create /sc minute /mo 1 /tn "eviltask" /tr C:\tools\shell.cmd /ru "SYSTEM"
```
{% endcode %}

## Observations

Note that processes spawned as scheduled tasks have `taskeng.exe` process as their parent:

![](../../.gitbook/assets/schtask-ancestry.png)

Monitoring and inspecting commandline arguments and established network connections by processes can help uncover suspicious activity:

![](../../.gitbook/assets/schtasks-created.png)

![](../../.gitbook/assets/schtask-connection.png)

Also, look for events 4698 indicating new scheduled task creation:

![](../../.gitbook/assets/schtasks-created-new-task.png)

### Lateral Movement

Note that when using schtasks for lateral movement, the processes spawned do not have taskeng.exe as their parent, rather - svchost:

{% code title="attacker@victim" %}
```bash
schtasks /create /sc minute /mo 1 /tn "eviltask" /tr calc /ru "SYSTEM" /s dc-mantvydas /u user /p password
```
{% endcode %}

![](../../.gitbook/assets/schtasks-remote.png)

## References

{% embed url="https://attack.mitre.org/wiki/Technique/T1053" %}

{% embed url="https://docs.microsoft.com/en-us/windows/desktop/taskschd/schtasks" %}

