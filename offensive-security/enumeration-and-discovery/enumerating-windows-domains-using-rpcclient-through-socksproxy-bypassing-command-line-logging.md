# Enumerating Windows Domains with rpcclient through SocksProxy == Bypassing Command Line Logging

This lab shows how it is possible to bypass commandline argument logging when enumerating Windows environments, using Cobalt Strike and its socks proxy \(or any other post exploitation tool that supports socks proxying\). 

In other words - it's possible to enumerate AD \(or create/delete AD users, etc.\) without the likes of:

* net user
* net user &lt;bla&gt; /domain
* net user &lt;bla&gt; &lt;bla&gt; /add /domain
* net localgroup
* net groups /domain
* and similar commands

...which most likely are monitored by the blue team.

## Assumption

In this lab, it is assumed that the attacker/operator has gained:

* code execution on a target system and the beacon is calling back to the team server
* valid set of domain credentials for any `authenticated user`

## Lab Environment

| IP | What's behind |
| :--- | :--- |
| 10.0.0.5 | attacker with kali and `rpcclient` |
| 10.0.0.2 | compromised Windows system `WS01` |
| 10.0.0.6 | Windows DC `DC01` to be interrogated by 10.0.0.5 via 10.0.0.2 |
| 10.0.0.7 | Windows box `WS02` to be interrogated by 10.0.0.5 via 10.0.0.2 |

## Execution

The below shows a couple of things. First one - two Cobalt Strike sessions:

* PID 4112 - original beacon
* PID 260 - beacon injected into dllhost process

Second - attacker opens a socks4 proxy on port 7777 on his local kali machine \(10.0.0.5\) by issuing:

{% code title="attacker@cobaltstrike" %}
```text
socks 7777
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-02-05-00-08-58.png)

This means that the attacker can now use proxychains to proxy traffic from their kali box through the beacon to the target \(attacker ---&gt; beacon ---&gt; end target\).

Let's see how this works by firstly updating the proxychains config file:

{% code title="attacker@kali" %}
```text
nano /etc/proxychains.conf
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-02-04-23-20-21.png)

### Enumeration

Once proxychains are configured, the attacker can start enumerating the AD environment through the beacon like so:

{% code title="attacker@kali" %}
```text
proxychains rpcclient 10.0.0.6 -U spotless
enumdomusers
```
{% endcode %}

![Victim \(10.0.0.2\) is enumerating DC \(10.0.0.6\) on behalf of attacker \(10.0.0.5\)](../../.gitbook/assets/screenshot-from-2019-02-05-20-22-43.png)

Moving on, same way, they can query info about specific AD users:

{% code title="attacker@kali" %}
```text
queryuser spotless
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-02-04-23-34-33.png)

Enumerate current user's privileges and many more \(consult rpcclient for all available commands\):

{% code title="attacker@kali" %}
```text
enumprivs
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-02-04-23-34-42.png)

Finally, of course they can run nmap if needed:

{% code title="attacker@kali" %}
```csharp
proxychains nmap 10.0.0.6 -T4 -p 21,22,23,53,80,443,25 -sT
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-02-04-23-36-48.png)

### Impacket

Impacket provides even more tools to enumerate remote systems through compromised boxes. See the below example gif. 

This is what happens - attacker \(10.0.0.5\) uses proxychains with impacket's reg utility to retrieve the hostname of the box at 10.0.0.7 \(WS02\) via the compromised \(CS beacon\) box 10.0.0.2 \(WS01\):

{% code title="attacker@kali" %}
```csharp
proxychains reg.py offense/administrator:123456@10.0.0.2 -target-ip 10.0.0.7 query -keyName hklm\system\currentcontrolset\control\computername\computername
```
{% endcode %}

The below shows traffic captures that illustrate that the box 10.0.0.2 enumerates 10.0.0.7 using SMB traffic only:

![](../../.gitbook/assets/peek-2019-02-09-19-50.gif)

Below further proves that the box 10.0.0.2 \(WS01 which acted as proxy\) did not generate any sysmon logs and the target box 10.0.0.7 \(WS02\) logged a couple of events, that most likely would not attract much attention from the blue teams:

![](../../.gitbook/assets/screenshot-from-2019-02-09-19-59-58.png)

## Observations

Note how only the SMB traffic between the compromised system and the DC is generated, but no new processes are spawned by the infected `dllhost` process:

![](../../.gitbook/assets/peek-2019-02-05-20-24.gif)

![](../../.gitbook/assets/screenshot-from-2019-02-04-23-18-20.png)

## References

{% embed url="https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html" %}

{% embed url="https://github.com/SecureAuthCorp/impacket/tree/master/examples" %}

{% embed url="https://www.cobaltstrike.com/help-socks-proxy-pivoting" %}

{% embed url="https://www.youtube.com/watch?v=l8nkXCOYQC4&index=19&list=WL&t=7s" %}



