# Windows Kernel Drivers 101

{% hint style="info" %}
Work In Progress
{% endhint %}

This living document captures some of the Kernel Driver and OS related concepts that I encounter as I study Windows kernel driver development.

## Driver Types

There are many different types of drivers, but I am mostly interested in `Sofware Drivers`.

### Software Driver

* Not associated with any device
* Useful for running code in the kernel mode
* Can also be a user mode driver
* Drivers can be developed with Kernel-Mode Driver Framework \(KMDF\) and Windows Driver Model \(WDM\)

## KMDF vs WDM

* WDM is very closely tied to the OS and interacts with the it calling system service routines directly
* KMDF is a framework that abstracts a lot of driver development and allows the developer to focus on his/her driver rather than focusing on OS programming intricacies
* KMDF is recommended and a preferred driver development model over WDM in most cases

## I/O Manager

* I/O manager manages the communication between applications and the interfaces provided by device drivers
* I/O Manager creates a driver object \(`DRIVER_OBJECT`\) for each installed and loaded driver
* I/O Manager calls driver's `DriverEntry` routine, which supplies the driver'd DRIVER\_OBJECT address
* Accepts I/O requests, which usually originate from user-mode applications
* Creates IRPs to represent the I/O requests
* Routes the IRPs to the appropriate drivers

## Uncategorized Notes

* All drivers contain `DriverEntry` routine - similary to `main` routine of an executable and `DllMain` of a DLL. This routine gets called once the driver is loaded and started by the OS.
* Memory allocated in paged pool can be paged out to a disk, whereas memory allocated from a  nonpaged pool cannot
* Requests sent to drivers are encapsulated in I/O Request Packets \(IRP\)
* `DRIVER_OBJECT` represents the image of a loaded kernel-mode driver:
  * ```text
    typedef struct _DRIVER_OBJECT {
      CSHORT             Type;
      CSHORT             Size;
      PDEVICE_OBJECT     DeviceObject;
      ULONG              Flags;
      PVOID              DriverStart;
      ULONG              DriverSize;
      PVOID              DriverSection;
      PDRIVER_EXTENSION  DriverExtension;
      UNICODE_STRING     DriverName;
      PUNICODE_STRING    HardwareDatabase;
      PFAST_IO_DISPATCH  FastIoDispatch;
      PDRIVER_INITIALIZE DriverInit;
      PDRIVER_STARTIO    DriverStartIo;
      PDRIVER_UNLOAD     DriverUnload;
      PDRIVER_DISPATCH   MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
    } DRIVER_OBJECT, *PDRIVER_OBJECT;
    ```
* `DRIVER_OBJECT` contains references to entry points of driver's standard routines \(i.e Unload\)
* Driver standard routines receive IRPs as input as well as a pointer to the target device object
* Drivers must create at least one device object \(`DEVICE_OBJECT`\) for each device
* Device objects serve as a target of operations performed on a the device
* Software only drivers that only handle I/O requests and do not pass them to hardware, still must create a device object to represent the target of its operations

## References

{% embed url="https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/packet-driven-i-o-with-reusable-irps" %}



