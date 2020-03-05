---
description: Using Windows Driver Model (WDM)
---

# Sending Commands from your Userland Program to your Kernel Driver via IOCTL

This is a quick lab that demonstrates how to:

* create a simple WDM kernel mode driver that can receive and respond to a custom defined input/output control code \(IOCTL\) that sent in from the userland program
* create a simple userland program that can sent a custom defined IOCTL to the kernel driver
* pass some data from the userland program to the kernel driver via `DeviceIoConctrol`
* pass some data from the kernelland to userland program

Below are the key code snippets that will make our kernel driver and the userland program.

## Kernel Driver

### DriverEntry

#### Populating DriverObject with Pointers

Inside driver's entry function, we populate our driver object with pointers to important routines that will be executed, for example, when the driver is unloaded or a handle to its device's symbolic link is obtained \(`IRP_MJ_CREATE`\) or closed \(`IRP_MJ_CLOSE`\):

![](../../.gitbook/assets/image%20%28118%29.png)

This is required, because these driver functions \(callbacks\) will be called by the OS when those events \(i.e someone trying to obtain a handle to your device, unload the driver or close device's handle\) will fire. We do not want the OS to not know what to do with our driver when the user attempts to unload it, therefore we tell it.

#### Creating Device and its Symbolic Link

This is where we create a device \(that we are writing the driver for\) and its symbolic link. The symbolic link is required if we want to access our driver from the userland and ask it to execute some code in respose to our custom defined IOCTL:

![](../../.gitbook/assets/image%20%2841%29.png)

![](../../.gitbook/assets/image%20%28445%29.png)

{% hint style="info" %}
IOCTL control code is a code that is sent to the device driver from the userland via a  `IRP_MJ_DEVICE_CONTROL` request sent via `DeviceIoControl` WinAPI. IOCTL control code tells the driver what action the driver needs to perform. For example, IOCTL code 0x202 \(`IOCTL_STORAGE_EJECT_MEDIA`\) could be sent to a USB/CDROM device and its  driver would carry out an appropriate action for the given device, i.e open the CD tray for a CD-ROM or eject the USB media storage.
{% endhint %}

Below shows the device name and its symbolic link we are using in this exercise:

![](../../.gitbook/assets/image%20%28180%29.png)

Below shows how after the device and its symbolic links are created by our driver once the `DriverEntry` routine was called. Also, the device `SpotlessDevice` is now visible inside WinObj:

![](../../.gitbook/assets/image%20%28158%29.png)

Additionally, we can see the symbolic link too - note how `SpotlessDeviceLink` symbolic link points to our device `\Device\SpotlessDevice`:

![](../../.gitbook/assets/image%20%28313%29.png)

### MajorFunctions

This function will handle IRPs that request \(`CreateFile`\)/close \(`CloseHandle`\) a handle to our device's symbolic link:

![](../../.gitbook/assets/image.png)

Below you can see how `IRP_MJ_CREATE` and `IRP_MJ_CLOSE` requests are issued \(for obtaining and closing the device's handle respectively\) are hit when we double click the `SpotlessDevice` in WinObj:

![](../../.gitbook/assets/device-handles.gif)

### HandleCustomIOCTL

This routine will handle the IOCTL request sent from our userland program - it will print a string that that will come from the userland. Additionally, it will send back a string to the userland:

![](../../.gitbook/assets/image%20%2837%29.png)

Worth noting that when `IoDeviceControl` is called in the userland with a custom IOCTL and the input data that we want to be sent to the kernel, the OS actually will intercept that request and package it into an I/O Packet \(IRP, a complex structure\) that will then be handed to our callback `HandleCustomIOCTL` that we registered in the DriverEntry routine for the IRP `IRP_MJ_DEVICE_CONTROL`.  IRP contains the incoming IOCTL code, the input data that was sent from the userland and also a buffer that the kernel driver code can use to send the response back to the userland.

### Defining Custom IOCTL

* IOCTL code needs to be defined both in the kernel driver as well as in the userland program
* IOCTL code is usually defined with a macro [`CTL_CODE`](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes). Microsoft suggests that you can choose any code starting from 0x800:

![](../../.gitbook/assets/image%20%28458%29.png)

## Userland Program

Below is the code that obtains a handle to the device `\Device\SpotlessDevice` via its symbolic link `\\.\SpotlessDeviceLink`, that we created earlier inside the driver's `DriverEntry` routine:

![](../../.gitbook/assets/image%20%28503%29.png)

Issuing a custom defined IOCTL to the driver and sending it a pointer to the string that comes as a commandline argument to our userland program: 

![](../../.gitbook/assets/image%20%28495%29.png)

Additionally, the above code prints out the string received from the kernel.

## Demo

Below shows how we execute our userland program with a string `spotless saying ola from userland` as an argument, that gets sent to the kernel driver via our custom defined `IOCTL_SPOTLESS` and receive some text back from the kernel:

![](../../.gitbook/assets/ioctl-driver-communication.gif)

## Code

* `driver.c` is our driver code that will receive and respond to IOCTL requests sent from the userland and send some data back to the userland program. 
* `userland.cpp` is the userland program sending IOCTL and receiving data from the kernel space

{% tabs %}
{% tab title="driver.c" %}
{% code title="" %}
```cpp
#include <wdm.h>

DRIVER_DISPATCH HandleCustomIOCTL;
#define IOCTL_SPOTLESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2049, METHOD_BUFFERED, FILE_ANY_ACCESS)
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\SpotlessDevice");
UNICODE_STRING DEVICE_SYMBOLIC_NAME = RTL_CONSTANT_STRING(L"\\??\\SpotlessDeviceLink");

void DriverUnload(PDRIVER_OBJECT dob)
{
	DbgPrint("Driver unloaded, deleting symbolic links and devices");
	IoDeleteDevice(dob->DeviceObject);
	IoDeleteSymbolicLink(&DEVICE_SYMBOLIC_NAME);
}

NTSTATUS HandleCustomIOCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stackLocation = NULL;
	CHAR *messageFromKernel = "ohai from them kernelz";

	stackLocation = IoGetCurrentIrpStackLocation(Irp);
	
	if (stackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_SPOTLESS)
	{
		DbgPrint("IOCTL_SPOTLESS (0x%x) issued", stackLocation->Parameters.DeviceIoControl.IoControlCode);
		DbgPrint("Input received from userland: %s", (char*)Irp->AssociatedIrp.SystemBuffer);
	}

	Irp->IoStatus.Information = strlen(messageFromKernel);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	
	DbgPrint("Sending to userland: %s", messageFromKernel);
	RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, messageFromKernel, strlen(Irp->AssociatedIrp.SystemBuffer));
	
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS MajorFunctions(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION stackLocation = NULL;
	stackLocation = IoGetCurrentIrpStackLocation(Irp);

	switch (stackLocation->MajorFunction)
	{
	case IRP_MJ_CREATE:
		DbgPrint("Handle to symbolink link %wZ opened", DEVICE_SYMBOLIC_NAME);
		break;
	case IRP_MJ_CLOSE:
		DbgPrint("Handle to symbolink link %wZ closed", DEVICE_SYMBOLIC_NAME);
		break;
	default:
		break;
	}
	
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) 
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	
	NTSTATUS status	= 0;

	// routine that will execute when our driver is unloaded/service is stopped
	DriverObject->DriverUnload = DriverUnload;
	
	// routine for handling IO requests from userland
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleCustomIOCTL;
	
	// routines that will execute once a handle to our device's symbolik link is opened/closed
	DriverObject->MajorFunction[IRP_MJ_CREATE] = MajorFunctions;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = MajorFunctions;
	
	DbgPrint("Driver loaded");

	IoCreateDevice(DriverObject, 0, &DEVICE_NAME, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DriverObject->DeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Could not create device %wZ", DEVICE_NAME);
	}
	else 
	{
		DbgPrint("Device %wZ created", DEVICE_NAME);
	}

	status = IoCreateSymbolicLink(&DEVICE_SYMBOLIC_NAME, &DEVICE_NAME);
	if (NT_SUCCESS(status))
	{
		DbgPrint("Symbolic link %wZ created", DEVICE_SYMBOLIC_NAME);
	}
	else
	{
		DbgPrint("Error creating symbolic link %wZ", DEVICE_SYMBOLIC_NAME);
	}
	
	return STATUS_SUCCESS;
}
```
{% endcode %}
{% endtab %}

{% tab title="userland.cpp" %}
```cpp
#include <iostream>
#include <Windows.h>

#define IOCTL_SPOTLESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2049, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main(char argc, char ** argv)
{
    HANDLE device = INVALID_HANDLE_VALUE;
    BOOL status = FALSE;                 
    DWORD bytesReturned = 0;
    CHAR inBuffer[128] = {0};
    CHAR outBuffer[128] = {0};

    RtlCopyMemory(inBuffer, argv[1], strlen(argv[1]));
    
    device = CreateFileW(L"\\\\.\\SpotlessDeviceLink", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
    
    if (device == INVALID_HANDLE_VALUE)
    {
        printf_s("> Could not open device: 0x%x\n", GetLastError());
        return FALSE;
    }

    printf_s("> Issuing IOCTL_SPOTLESS 0x%x\n", IOCTL_SPOTLESS);
    status = DeviceIoControl(device, IOCTL_SPOTLESS, inBuffer, sizeof(inBuffer), outBuffer, sizeof(outBuffer), &bytesReturned, (LPOVERLAPPED)NULL);
    printf_s("> IOCTL_SPOTLESS 0x%x issued\n", IOCTL_SPOTLESS);
    printf_s("> Received from the kernel land: %s. Received buffer size: %d\n", outBuffer, bytesReturned);

    CloseHandle(device);
}
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://www.osronline.com/article.cfm%5Eid=92.htm" %}

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol" %}

{% embed url="https://www.drdobbs.com/windows/sending-ioctls-to-windows-nt-drivers/184416453" %}

{% embed url="https://cylus.org/windows-drivers-part-2-ioctls-c678526f90ae" %}

{% embed url="https://ericasselin.com/userlandkernel-communication-deviceiocontrol-method" %}

