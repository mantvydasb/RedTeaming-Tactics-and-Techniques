# Preventing 3rd Party DLLs from Injecting into your Processes

It is possible to launch processes in such a way that Windows will prevent non Microsoft signed binaries from being injected into that process. This may be useful for evading AVs/EDRs that perform userland hooking by injecting their DLLs into each process run on the system. 

## UpdateProcThreadAttribute

First method of achieving the objective is brought to us by [UpdateProcThreadAttribute](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)  and one of the attributes it allows us manipulate -`PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`

Below code shows how to create spawn a new notepad process with a mitigation policy that will not allow any non MS Signed binaries to be injected to it:

{% embed url="https://gist.github.com/mantvydasb/89a9c01327fdd9d93b8b95274319f532" %}

Compiling and executing the above code will execute notepad.exe with a process mitigation policy that prevents non Microsoft binaries from getting injected into it. This can be confirmed with process hacker:

![](../../.gitbook/assets/image%20%2826%29.png)

## SetProcessMitigationPolicy

Another method allows to set the mitigation policy for the calling process itself:

```cpp
PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sp = {};
sp.MicrosoftSignedOnly = 1;
SetProcessMitigationPolicy(ProcessSignaturePolicy, &sp, sizeof(sp));
```

![](../../.gitbook/assets/image%20%28194%29.png)

## References

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute" %}

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy" %}

