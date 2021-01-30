# WinRS for Lateral Movement

It's possible to use a native Windows binary `winrs` to connect to a remote endpoint via `WinRM` like so:

```text
winrs -r:ws01 "cmd /c hostname & notepad"
```

Below shows how we connect from `DC01` to `WS01` and execute two processes `hostname`,`notepad` and the process partent/child relationship for processes spawned by the `winrshost.exe`:

![](../../.gitbook/assets/image%20%28534%29.png)

## References

{% embed url="https://bohops.com/2020/05/12/ws-management-com-another-approach-for-winrm-lateral-movement/amp/" %}

