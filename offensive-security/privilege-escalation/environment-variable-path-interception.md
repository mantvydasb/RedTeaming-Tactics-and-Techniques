# Environment Variable $Path Interception

It's possible to abuse `$PATH` environment variable to elevate privileges if the variable:

* contains a folder that a malicious user can write to
* that folder precedes c:\windows\system32\

Below is an example, showing how c:\temp precedes c:\windows\system32:

![](../../.gitbook/assets/image%20%2870%29.png)

Let's make sure c:\temp is \(M\)odifiable by low privileged users:

![](../../.gitbook/assets/image%20%28512%29.png)

Let's now drop our malicious file \(calc.exe in this case\) into c:\temp and call it cmd.exe:

![](../../.gitbook/assets/image%20%28496%29.png)

Now, the next time a high privileged user invokes cmd.exe, our malicious cmd.exe will be invoked from the c:\temp:

![](../../.gitbook/assets/image%20%28296%29.png)

This can be very easily abused in environments where software deployment packages call powershell, cmd, cscript and other similar system binaries with `NT SYSTEM` privileges to carry out their tasks.

