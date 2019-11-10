---
description: Discovery
---

# T1010: Application Window Discovery

Retrieving running application window titles:

{% tabs %}
{% tab title="attacker@victim" %}
```csharp
get-process | where-object {$_.mainwindowtitle -ne ""} | Select-Object mainwindowtitle
```
{% endtab %}
{% endtabs %}

![](../../.gitbook/assets/window-titles.png)

A COM method that also includes the process path and window location coordinates:

{% tabs %}
{% tab title="attacker@victim" %}
```csharp
[activator]::CreateInstance([type]::GetTypeFromCLSID("13709620-C279-11CE-A49E-444553540000")).windows()
```
{% endtab %}
{% endtabs %}

![](../../.gitbook/assets/annotation-2019-06-18-224603.png)

## References

{% embed url="https://attack.mitre.org/wiki/Technique/T1010" %}



