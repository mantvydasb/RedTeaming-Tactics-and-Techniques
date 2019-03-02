---
description: Discovery
---

# T1010: Application Window Discovery

Retrieving running application window titles:

{% code-tabs %}
{% code-tabs-item title="attacker@victim" %}
```csharp
get-process | where-object {$_.mainwindowtitle -ne ""} | Select-Object mainwindowtitle
```
{% endcode-tabs-item %}
{% endcode-tabs %}

![](../.gitbook/assets/window-titles.png)

## References

{% embed url="https://attack.mitre.org/wiki/Technique/T1010" %}



