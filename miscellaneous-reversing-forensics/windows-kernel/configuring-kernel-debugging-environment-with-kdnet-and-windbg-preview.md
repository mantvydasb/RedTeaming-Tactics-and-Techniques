# Configuring Kernel Debugging Environment with kdnet and WinDBG Preview

This is a quick note showing how to start debugging Windows kernel using [kdnet.exe](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools) and WinDBG Preview \(the new WinDBG you can get from the Windows Store\).

## Terms

* Debugger - local host on which WinDBG will run. In my case a host with IP `192.168.2.79`
* Debuggee - remote host which will be debugged by the host running the debugger. In my case - a host with IP `192.168.2.68`

## On the Debuggee

Copy over kdnet.exe and VerifiedNICList.xml to the debugee host. Get these files from a host that has Windows Development Kit installed, in C:\Program Files \(x86\)\Windows Kits\10\Debuggers\x64:

![](../../.gitbook/assets/image%20%28522%29.png)

Then in an elevated prompt:

```text
kdnet 192.168.2.79 50001
```

The bewlow shows how kdnet prints out the command that needs to be run on the debugger host:

```text
windbg -k net:port=50001,key=1dk3k2bprui6m.26vzkoub4jmjl.3v6rvfqjys3ek.6kyxal1u1w6s
```

![](../../.gitbook/assets/image%20%2843%29.png)

Copy and paste to a notepad and reboot the debugee.

## On the Debugger

In WinDBG Preview, navigate to: start debugging &gt; attach to kernel and enter the port and the key you got from running the kdnet on the debugge host:

![](../../.gitbook/assets/image%20%28113%29.png)

Click OK and you should now be ready to start debugging the host `192.168.2.68`:

![](../../.gitbook/assets/kerneldebuggingconnect.gif)

## References

{% embed url="https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-a-network-debugging-connection-automatically" %}

