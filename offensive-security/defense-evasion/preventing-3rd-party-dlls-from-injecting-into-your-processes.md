# Preventing 3rd Party DLLs from Injecting into your Malware

It is possible to launch a new process in such a way that Windows will prevent non Microsoft signed binaries from being injected into that process. This may be useful for evading some AVs/EDRs that perform userland hooking by injecting their DLLs into running process.

## UpdateProcThreadAttribute

First method of achieving the objective is brought to us by [UpdateProcThreadAttribute](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)  and one of the attributes it allows us set -`PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`

Below code shows how to create a new notepad process with a mitigation policy that will not allow any non MS Signed binaries to be injected to it:

{% embed url="https://gist.github.com/mantvydasb/89a9c01327fdd9d93b8b95274319f532" %}

Compiling and executing the above code will execute notepad.exe with a process mitigation policy that prevents non Microsoft binaries from getting injected into it. This can be confirmed with process hacker:

![](../../.gitbook/assets/image%20%2827%29.png)

Below GIF shows the mitigation policy in action - non MS signed binaries are blocked, but a Microsoft binaries are let through:

![Non Microsoft DLL being prevented from loading](../../.gitbook/assets/prevention.gif)

It is worth mentioning that this is exactly what the `blockdlls` does under the hood in [Cobalt Strike](https://blog.cobaltstrike.com/2019/05/02/cobalt-strike-3-14-post-ex-omakase-shimasu/).

## SetProcessMitigationPolicy

While playing with the first method, I stumbled upon a `SetProcessMitigationPolicy` API that allows us to set the mitigation policy for the calling process itself ratther than for child processes as with the first technique:

{% code-tabs %}
{% code-tabs-item title="mitigationpolicy.cpp" %}
```cpp
PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sp = {};
sp.MicrosoftSignedOnly = 1;
SetProcessMitigationPolicy(ProcessSignaturePolicy, &sp, sizeof(sp));
```
{% endcode-tabs-item %}
{% endcode-tabs %}

![](../../.gitbook/assets/image%20%28201%29.png)

In my limited testing, using `SetProcessMitigationPolicy` did not prevent a well known EDR solution from injecting its DLL into my process on process creation. A quick debugging session confirmed why - the mitigation policy gets applied after the DLL has already been injected. Once the process has been initialized and is running, however, any further attempts to inject non Microsoft signed binaries will be prevented:

![](../../.gitbook/assets/prevention.gif)

If you've successfully abused `SetProcessMitigationPolicy`, I would like to hear from you.

## Detection

I am sure there are better ways \(if you know, I would like to hear\), but here's the idea - use a powershell's `Get-ProcessMitigation` cmdlet to enumerate the processes that run with `MicrosoftSignedOnly` mitigation set, investigate, baseline, repeat:

```csharp
get-process | select -exp processname -Unique | % { Get-ProcessMitigation -ErrorAction SilentlyContinue -RunningProcesses $_ | select processname, Id, @{l="Block non-MS Binaries"; e={$_.BinarySignature|select -exp MicrosoftSignedOnly} } }
```

Below shows how the notepad.exe only allows MS Signed binaries to be injected into its process:

![](../../.gitbook/assets/image%20%28159%29.png)

## References

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute" %}

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy" %}

{% embed url="https://blog.cobaltstrike.com/2019/05/02/cobalt-strike-3-14-post-ex-omakase-shimasu/" %}

