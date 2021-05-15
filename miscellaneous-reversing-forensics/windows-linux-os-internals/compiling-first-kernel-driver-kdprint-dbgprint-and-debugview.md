# Compiling a Simple Kernel Driver, DbgPrint, DbgView

## Simple Windows Driver Framework \(WDF\) Kernel Driver

Select Kernel Mode Driver, Emtpy \(KMDF\) from templates:

![](../../.gitbook/assets/image%20%28509%29.png)

## Create a driver.c

Create a new `driver.c` file under `Source Files`:

![](../../.gitbook/assets/image%20%2881%29.png)

## Add Driver Code

{% code title="driver.c" %}
```c
#include <ntddk.h>
#include <wdf.h>

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD EvtDriverDeviceAdd;
EVT_WDF_DRIVER_UNLOAD UnloadDriver;

_Use_decl_annotations_
void UnloadDriver(IN WDFDRIVER driver)
{
    UNREFERENCED_PARAMETER(driver);
    DbgPrint("Driver unloaded");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG config;
    WDF_DRIVER_CONFIG_INIT(&config, EvtDriverDeviceAdd);
    config.EvtDriverUnload = UnloadDriver;
    NTSTATUS status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
    
    DbgPrint("Driver loaded");

    return status;
}

NTSTATUS EvtDriverDeviceAdd(_In_ WDFDRIVER Driver,_Inout_ PWDFDEVICE_INIT DeviceInit)
{
    UNREFERENCED_PARAMETER(Driver);
    WDFDEVICE device;
    NTSTATUS status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    
    return status;
}
```
{% endcode %}

## Enable DbgPrint Monitoring for WinDBG

Change the debug output verbosity:

```text
ed kd_default_mask 0xf
```

![](../../.gitbook/assets/image%20%2858%29.png)

[Starting the driver](loading-a-windows-kernel-driver-osr-driver-loader-debugging-with-source-code.md) allows us to see the debug output in WinDBG:

![](../../.gitbook/assets/image%20%28446%29.png)

## Enable DbgPrint Monitoring for DbgView

Create a sub-key `Debug Print Filter` if it does not exist:

```text
Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter
```

Add a new DWORD value `DEFAULT` and set its Data field to `0xf`:

![](../../.gitbook/assets/image%20%28413%29.png)

If we load the driver now and start it, we can see the debug output in DbgView too:

![](../../.gitbook/assets/image%20%28175%29.png)

## Requested Control is Not Valid for This Service

The below error message is seen if you attempt to stop the WDF driver via OSR Driver Loader or the native sc.exe, even if you have defined the driver unloading routine:

![](../../.gitbook/assets/image%20%28136%29.png)

I could not find a solution to this, but WDM driver has no such issue - see the code below.

## Simple Windows Driver Model \(WDM\) Kernel Driver Load and Unload

Below is a simple WDM driver that can be compiled and then loaded and stopped with OSR Driver Loader:

```c
#include <ntddk.h>

void DriverUnload(PDRIVER_OBJECT dob)
{
	UNREFERENCED_PARAMETER(dob);
	DbgPrint("Driver unloaded");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = DriverUnload;
	DbgPrint("Driver loaded");

	return STATUS_SUCCESS;
}
```

Below shows how our driver is loaded and unloaded via OSR Loader while DbgView prints our DbgPrint output defined in the above `DriverEntry` and `DriverUnload` routines:

![](../../.gitbook/assets/image%20%28503%29.png)

## References

{% embed url="https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/writing-a-very-small-kmdf--driver" %}

{% embed url="http://www.osronline.com/article.cfm%5earticle=295.htm" %}

