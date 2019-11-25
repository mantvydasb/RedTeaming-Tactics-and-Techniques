---
description: >-
  Concealing attacking hosts through with redirectors/traffic forwarders using
  iptables or socat
---

# HTTP Forwarders / Relays

## Purpose

Re-directors or traffic forwarders are essentially proxies between the red teaming server \(say the one for sending phishing emails or a C2\) and the victim - `victim <> re-director <> team server`

The purpose of the re-director host is as usual:

* Obscure the red teaming server by concealing its IP address. In other words - the victim will see traffic coming from the re-director host rather than the team server.
* If incident responders detect suspicious activity originating from the redirector, it can be "easily" decommissioned and replaced with another one, which is "easier" than rebuilding the team server.

## HTTP Forwarding with iptables

I will explore simple HTTP forwarders which are just that - they simply listen on a given interface and port and forward all the traffic they receive on that port, to a listener port on the team server.

My environment in this lab:

* Team server and a listening port: `10.0.0.2:80`
* Re-director host and a listening port: `10.0.0.5:80`
* Victim host: `10.0.0.11`

An easy way to create an HTTP re-director is to use a Linux box and its iptables capability.

Below shows how to turn a Linux box into an HTTP re-director. In this case, all the HTTP traffic to `10.0.0.5:80` \(redirector\) will be forwarded to `10.0.0.2:80` \(team server\) :

```csharp
iptables -I INPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 10.0.0.2:80
iptables -t nat -A POSTROUTING -j MASQUERADE
iptables -I FORWARD -j ACCEPT
iptables -P FORWARD ACCEPT
sysctl net.ipv4.ip_forward=1
```

Checking that the iptables rules were created successfully:

![](../../.gitbook/assets/redirectors-iptables.png)

### Testing iptables

Let's simulate a simplified reverse shell from the victim system 10.0.0.11 to the attacking system 10.0.0.2 using our redirector system 10.0.0.5 as a proxy and inspect the traffic crossing over the wire - if the redirector was setup correctly, we should see that systems 10.0.0.11 and 10.0.0.2 will not be communicating directly - all the traffic will be flowing through the box at 10.0.0.5 and 10.0.0.2 \(attacking system\) will not be visible to the victim 10.0.0.11:

![](../../.gitbook/assets/redirector.gif)

Having a closer look at the traffic/conversations between the endpoints, we can clearly see that at no point the victim system 10.0.0.11 communicated directly with the attacking system 10.0.0.2 - all communications were flowing through the redirector host 10.0.0.5 as described earlier:

![](../../.gitbook/assets/redirector-conversations.png)

{% file src="../../.gitbook/assets/redirector.pcapng" caption="Redirector Network Trace" %}

## HTTP Forwarding with SOCAT

SOCAT is another tool that can be used to do the "dumb pipe" traffic forwarding. The environment in this exercise remains the same as in the previous scenario.

Setting up an HTTP redirector with socat:

```csharp
socat TCP4-LISTEN:80,fork TCP4:10.0.0.2:80
```

![](../../.gitbook/assets/redirector-socat.gif)

## References

{% embed url="https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki\#https" caption="" %}

{% embed url="https://www.frozentux.net/iptables-tutorial/chunkyhtml/x4033.html" caption="" %}

{% embed url="http://linux-training.be/networking/ch14.html" caption="" %}

{% embed url="http://technostuff.blogspot.com/2008/10/some-useful-socat-commands.html" caption="" %}

{% embed url="https://www.thegeekstuff.com/2011/01/iptables-fundamentals/" caption="" %}

