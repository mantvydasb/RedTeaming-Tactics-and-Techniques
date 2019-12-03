# Interrupt Descriptor Table - IDT

{% hint style="info" %}
WIP
{% endhint %}

## At a Glance

* Interrupts could be thought of as `notifications` to the CPU that tells it that `some event` triggered on the system. Classic examples of interrupts are hardware interrupts such as mouse or keyboard interactions, network packet activity and hardware generated exceptions such as a division by zero or a breakpoint \(interrupts 0x00 and 0x03 respectively\)
* Once the CPU gets interrupted, it needs to stop doing what it was doing and respond to that interrupt immediately
* CPU knows how to respond \(what kernel routines to execute\) to the received interrupts by looking up Interrupt Service Routines \(ISR\) that are found in the Interrupt Descriptor Table \(IDT\)
* IDT is a kernel memory structure
  * Pointer to an IDT is stored in an `IDTR` register for each physical processor or in other words, each processor has its own `IDTR` register pointing to its own Interrupt Descriptor Table
* IDT can contain up to 256 descriptors, 8 bytes each

## Dumping IDT

We can dump the IDT and see addresses of Interrupt Service Routines for a given interrupt. Below is a snippet of the Interrupt Descriptor Table:

```erlang
kd> !idt

Dumping IDT: fffff80091456000

00:	fffff8008f37e100 nt!KiDivideErrorFaultShadow
01:	fffff8008f37e180 nt!KiDebugTrapOrFaultShadow	Stack = 0xFFFFF8009145A9E0
02:	fffff8008f37e200 nt!KiNmiInterruptShadow	Stack = 0xFFFFF8009145A7E0
03:	fffff8008f37e280 nt!KiBreakpointTrapShadow
...snip...
90:	fffff8008f37f680 i8042prt!I8042MouseInterruptService (KINTERRUPT ffffd4816353e8c0)
a0:	fffff8008f37f700 i8042prt!I8042KeyboardInterruptService (KINTERRUPT ffffd4816353ea00)
...snip...
```

Below shows the IDT/IRS in action:

* IDT table is dumped with !idt
* In the IDT, Interrupt a0 at fffff8008f37f700 located. It is pointing to an IRS `i8042prt!I8042KeyboardInterruptService`. This routine is executed when a keyboard event such as a keypress is registered on the OS
* Putting a breakpoint on 

  `i8042prt!I8042KeyboardInterruptService`

* Once the breakpoint is set, a key is pressed on the OS login prompt on the left and our breakpoint is hit, confirming that 

  `i8042prt!I8042KeyboardInterruptService` indeed handles keyboard interrupts

![](../../.gitbook/assets/keyboard-interrupt.gif)

## KINTERUPT

KINTERUPT is a kernel memory structure that contains a lot of information about interrupts. The key member of this structure for this lab is the member located at offset 0x18 of the structure, which contains a pointer to the Interupt Service Routine - the routine responsible for handling the interrupt:

```text
dt nt!_KINTERRUPT
   +0x000 Type             : Int2B
   +0x002 Size             : Int2B
   +0x008 InterruptListEntry : _LIST_ENTRY
   +0x018 ServiceRoutine   : Ptr64     unsigned char 
   ...
   +0x0f8 Padding          : [8] UChar
```

From earlier, we know that the ISR `i8042prt!I8042KeyboardInterruptService` for keyboard interrupts is located at `ffffd4816353ea00`, therefore we can inspect the KINTERUPT structure by overlaying with it memory contents at `ffffd4816353ea00`

```erlang
dt nt!_KINTERRUPT ffffd4816353ea00
```

...where we confirm that the Interrupt Service Routine is again pointing at `i8042prt!I8042KeyboardInterruptService`: 

![](../../.gitbook/assets/image%20%28290%29.png)

## References

{% embed url="https://nagareshwar.securityxploded.com/2014/03/20/code-injection-and-api-hooking-techniques/" %}

{% embed url="https://www.linux.com/tutorials/kernel-interrupt-overview/" %}

{% embed url="https://en.wikipedia.org/wiki/Interrupt\_handler" %}

{% embed url="https://relearex.wordpress.com/2017/12/27/hooking-series-part-ii-interrupt-descriptor-table-hooking/" %}





