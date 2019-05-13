---
description: >-
  This lab explores a technique that allows a SYSTEM account to move laterally
  through the network using RDP without the need for credentials.
---

# T1076: RDP Hijacking for Lateral Movement with tscon

## Execution

It is possible by design to switch from one user's desktop session to another through the Task Manager \(one of the ways\).

Below shows that there are two users on the system and currently the administrator session is in active:

![](../../.gitbook/assets/rdp-admin.png)

Let's switch to the `spotless` session - this requires knowing the user's password, which for this exercise is known, so lets enter it:

![](../../.gitbook/assets/rdp-login.png)

![](../../.gitbook/assets/rdp-password.png)

We are now reconnected to the `spotless` session:

![](../../.gitbook/assets/rdp-spotless.png)

Now this is where it gets interesting. It is possible to reconnect to a users session without knowing their password if you have `SYSTEM` level privileges on the system.   
Let's elevate to `SYSTEM` using psexec \(privilege escalation exploits, service creation or any other technique will also do\):

```text
psexec -s cmd
```

![](../../.gitbook/assets/rdp-system.png)

Enumerate available sessions on the host with `query user`:

![](../../.gitbook/assets/rdp-sessions.png)

Switch to the `spotless` session without getting requested for a password by using the native windows binary `tscon.exe`that enables users to connect to other desktop sessions by specifying which session ID \(`2` in this case for the `spotless` session\) should be connected to which session \(`console` in this case, where the active `administator` session originates from\):

```csharp
cmd /k tscon 2 /dest:console
```

![](../../.gitbook/assets/rdp-hijack-no-password.png)

Immediately after that, we are presented with the desktop session for `spotless`:

![](../../.gitbook/assets/rdp-spotless-with-system.png)

## Observations

Looking at the logs, `tscon.exe` being executed as a `SYSTEM` user is something you may want to investigate further to make sure this is not a lateral movement attempt:

![](../../.gitbook/assets/rdp-logs%20%281%29.png)

Also, note how `event_data.LogonID` and event\_ids `4778` \(logon\) and `4779` \(logoff\) events can be used to figure out which desktop sessions got disconnected/reconnected:

![Administrator session disconnected](../../.gitbook/assets/rdp-session-disconnect.png)

![Spotless session reconnected \(hijacked\)](../../.gitbook/assets/rdp-session-reconnect.png)

Just reinforcing the above - note the usernames and logon session IDs:

![](../../.gitbook/assets/rdp-logon-sessions.png)

## References

{% embed url="http://blog.gentilkiwi.com/securite/vol-de-session-rdp" %}

{% embed url="http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html" %}

{% embed url="https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4778" %}

{% embed url="https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tscon" %}



