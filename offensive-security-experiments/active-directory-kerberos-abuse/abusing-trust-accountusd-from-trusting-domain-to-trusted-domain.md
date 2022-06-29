# Abusing Trust Account$: From Trusting Domain to Trusted Domain

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

This technique is possible, because once a trust relationship between domains is established, a trust account for the trusting domain is created in the trusted domain and it's possible to compromise that account's password hash, which enables an attacker to authenticate to the trusted domain as the trusts account.

In our situation, considering that `first.local` is a trusted domain trusted by the trusting domain second.local, the trust account `first.local\second$` (user account `second$` in the domain `first.local`) will be created.&#x20;

`first.local\second$` is the account we want to and CAN compromise if we have domain admin privileges on `second.local`.

## Walkthrough

Let's check some of the things we touched on in the overview.

```
get-adtrust -filter *
```

## References

{% embed url="https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted" %}
