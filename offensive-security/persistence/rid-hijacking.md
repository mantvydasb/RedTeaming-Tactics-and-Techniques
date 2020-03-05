# RID Hijacking

RID \(Relative ID, part of the SID \(Security Identifier\)\) hijacking is a persistence technique, where an attacker with SYSTEM level privileges assigns an RID 500 \(default Windows administrator account\) to some low privileged user, effectively making the low privileged account assume administrator privileges on the next logon.

This techniques was originally researched by [Sebastian Castro](https://twitter.com/r4wd3r) -   [https://r4wsecurity.blogspot.com/2017/12/rid-hijacking-maintaining-access-on.html](https://r4wsecurity.blogspot.com/2017/12/rid-hijacking-maintaining-access-on.html)

## Execution

This lab assumes that we've compromised the WS01 machine and have `NT SYSTEM` access to it.

Below shows that the user `hijacked` is a low privileged user and has an RID of 1006 or 0x3ee:

![](../../.gitbook/assets/image%20%28427%29.png)

If we try to write something to c:\windows\ with the user `hijacked`, as expected, we get `Access is Denied`:

![](../../.gitbook/assets/image%20%28132%29.png)

HKEY\_LOCAL\_MACHINE\SAM\SAM\Domains\Account\Users\000003EE stores some information about the user`hijacked` that is used by LSASS during the user logon/authentication process. Specifically, at offset `0030` in the value `F` there are bytes that denote user's RID, which in our case are 03ee \(1006\) for the user `hijacked`:

![](../../.gitbook/assets/image%20%28447%29.png)

We can change those 2 bytes to 0x1f4 \(500 - default administrator RID\), which will effectively make the user `hijacked` assume administrator privileges:

![](../../.gitbook/assets/image%20%2893%29.png)

## Demo

After changing the `hijacked` RID from 3ee to 1f4 and creating a new logon session, we can see that the user `hijacked` is now allowed to write to c:\windows\, suggesting it now has administrative privileges:

![](../../.gitbook/assets/rid-hijacking.gif)

Note, that the user `hijacked` still does not belong to local administrators group, but its RID is now 500:

![](../../.gitbook/assets/image%20%28271%29.png)

## Detection

Monitor HKEY\_LOCAL\_MACHINE\SAM\SAM\Domains\Account\Users\\*\F for modifications, especially if they originate from unusual binaries.

## References

{% embed url="https://r4wsecurity.blogspot.com/2017/12/rid-hijacking-maintaining-access-on.html" %}

