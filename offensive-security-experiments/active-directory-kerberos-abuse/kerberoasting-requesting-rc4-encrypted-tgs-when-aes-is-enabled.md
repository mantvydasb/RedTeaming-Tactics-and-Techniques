# Kerberoasting: Requesting RC4 Encrypted TGS when AES is Enabled

It is possible to kerberoast a user account with SPN even if the account supports Kerberos AES encryption by requesting an RC4 ecnrypted \(instead of AES\) TGS which easier to crack.

## Execution

First off, let's confirm we have at least one user with an SPN set:

{% code title="attacker@victim" %}
```text
Get-NetUser -SPN sandy
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-05-06-15-37-30.png)

Since the user account does not support Kerberos AES ecnryption by default, when requesting a TGS ticket for kerberoasting with rubeus, we will get an RC4 encrypted ticket:

{% code title="attacker@victim" %}
```text
F:\Rubeus\Rubeus.exe kerberoast /user:sandy
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-05-06-15-39-53.png)

If the user is now set to support AES encryption:

![](../../.gitbook/assets/screenshot-from-2019-05-06-15-40-51.png)

By default, returned tickets will be encrypted with the highest possible encryption algorithm, which is AES:

{% code title="attacker@victim" %}
```text
F:\Rubeus\Rubeus.exe kerberoast /user:sandy
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-05-06-15-58-37.png)

## Requesting RC4 Encrypted Ticket

As mentioned in the beginning, it's still possible to request an RC4 ecnrypted ticket \(if RC4 is not disabled in the environment, which does not seem to be common yet\):

{% code title="attacker@victim" %}
```text
F:\Rubeus\Rubeus.exe kerberoast /tgtdeleg
```
{% endcode %}

Even though AES encryption is supported by both parties, a TGS ticket encrypted with RC4 \(encryption type 0x17/23\) was returned. Note that SOCs may be monitoring for tickets encrypted with RC4:

![](../../.gitbook/assets/screenshot-from-2019-05-06-16-03-06.png)

## References

{% embed url="https://www.harmj0y.net/blog/redteaming/kerberoasting-revisited/" %}

