# Preventing 3rd Party DLLs from Injecting into your Processes

It is possible to launch a new process in such a way that Windows will prevent non Microsoft signed binaries from being injected into that process. This may be useful for evading some AVs/EDRs that perform userland hooking by injecting their DLLs into running process.

## UpdateProcThreadAttribute

First method of achieving the objective is brought to us by [UpdateProcThreadAttribute](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)  and one of the attributes it allows us set -`PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`

Below code shows how to create a new notepad process with a mitigation policy that will not allow any non MS Signed binaries to be injected to it:

{% embed url="https://gist.github.com/mantvydasb/89a9c01327fdd9d93b8b95274319f532" %}

Compiling and executing the above code will execute notepad.exe with a process mitigation policy that prevents non Microsoft binaries from getting injected into it. This can be confirmed with process hacker:

![](../../.gitbook/assets/image%20%2826%29.png)

Below GIF shows the mitigation policy in action - non MS signed binaries are blocked, but a Microsoft binaries are let through:

![](../../.gitbook/assets/prevention.gif)

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

![](../../.gitbook/assets/image%20%28194%29.png)

In my limited testing, using `SetProcessMitigationPolicy` did not prevent a well known EDR solution from injecting its DLL into my process on process creation. A quick debugging session confirmed why - the mitigation policy gets applied after the DLL has already been injected. Once the process has been initialized and is running, however, any further attempts to inject non Microsoft signed binaries will be prevented:

![](../../.gitbook/assets/prevention.gif)

If you've successfully abused `SetProcessMitigationPolicy`, I would like to hear from you.

## References

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute" %}

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy" %}

