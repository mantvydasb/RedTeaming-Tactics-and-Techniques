---
description: 'Defense Evasion, Persistence'
---

# T1158: Hidden Files

## Execution

Hiding the file mantvydas.sdb using a native windows binary:

{% code title="attacker@victim" %}
```csharp
PS C:\experiments> attrib.exe +h .\mantvydas.sdb
```
{% endcode %}

Note how powershell \(or cmd\) says the file does not exist, however you can type out its contents if you know the file exists:

![](../../.gitbook/assets/attrib-nofile.png)

Note, that `dir /a:h` \(attribute: hidden\) reveals files with a "hidden" attribute set:

![](../../.gitbook/assets/attrib-reveal.png)

## Observations

As usual, monitoring commandline arguments may be a good idea if you want to identify these events:

![](../../.gitbook/assets/attrib-set.png)

## References

{% embed url="https://attack.mitre.org/wiki/Technique/T1158" %}



