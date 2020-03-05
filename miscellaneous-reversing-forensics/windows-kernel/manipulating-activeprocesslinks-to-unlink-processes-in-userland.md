# Manipulating ActiveProcessLinks to Hide Processes in Userland

The purpose of this lab is to look into how Windows kernel rootkits hide / unlink \(or used to\) processes in the userland for utilities trying to list all running processes on the system such as `Windows Task Manager`, `tasklist` or `Get-Process` cmdlet in Powershell.

This is going to be a high level overview and no kernel code will be written, instead, kernel memory structures will be manipulated manually with WinDBG.

{% hint style="info" %}
Lab is performed on Windows 10 Professional x64, 1903.
{% endhint %}

**Update 1**  
Some replies to my tweet to this post suggested that PatchGuard would normally kick-in and BSOD the OS, which I am sure is the case, although in my lab I experienced no BSODs even though the kernel stayed patched with an unlinked process for 12+ hours.

**Update 2**  
I realized that my Windows VM is running in test mode with no integrity checks, possibly explaining the lack os BSODs - unconfirmed.  
  
**Update 3**  
Thanks ****[**@**FuzzySec](https://twitter.com/FuzzySec) for clarifying the BSOD/PatchGuard matter!

![](../../.gitbook/assets/image%20%2834%29.png)

## Key Structures

We need to be familiar with two kernel memory structures before we proceed.

### \_EPROCESS <a id="_eprocess"></a>

`_EPROCESS` is a kernel memory structure that describes system processes \(or in other words - each process running on a system has its corresponding `_EPROCESS` object somewhere in the kernel\) as we know them. It contains details such as process image name, which desktop session it is running in, how many open handles to other kernel objects it has, what access token it has and much more.

Below shows a snippet of the structure and a highlighted a member that is **key** to this lab - `ActiveProcessLinks` . It is a pointer to a structure called `LIST_ENTRY`:

```text
dt _eprocess
```

![](../../.gitbook/assets/image%20%28189%29.png)

### \_LIST\_ENTRY

In programming, there is a data structure known as `doubly-linked list` . It contains records \(also called nodes\) that are linked to each other, meaning each node in the list contains two fields \(hence doubly\), that reference previous and the next record of that linked list.

Simplified \(head and tail omitted\) graphical representation of the doubly-linked list is shown below:

![](../../.gitbook/assets/image%20%28284%29.png)

`LIST_ENTRY` is the doubly-linked list equivalent data structure in Windows kernel and is defined as: 

```erlang
kd> dt _list_entry
ntdll!_LIST_ENTRY
   +0x000 Flink            : Ptr64 _LIST_ENTRY
   +0x008 Blink            : Ptr64 _LIST_ENTRY
```

...where `FLINK` \(forward link\) and `BLINK` \(backward link\) are the equivalents of `Next` and `Previous` references to the next and previous element in the list in our graphical representation of the doubly-linked list discussed above.

## LIST\_ENTRY Importance

All Windows processes have their corresponding kernel objects in the form of an EPROCESS kernel structure. All those EPROCESS objects are stored in a doubly-linked list.

Effectively, this means that when a `cmd /c tasklist` or `get-process` is invoked to get a list of all running processes on the system, Windows walks through the doubly-linked list of EPROCESS nodes, utilizing the `LIST_ENTRY` structures and retrieves information about all currently active processes.

Below is a simplified visualization of the above:

![](../../.gitbook/assets/image%20%28454%29.png)

## Goal of the Lab

With all of the above information, we can now define what we're trying to do in the lab - we want to hide a process of our choice from being shown in a process list when a `get-process` cmdlet or similar is issued in the userland.

Below is a simplified diagram illustrating how this will be achieved by manually manipulating kernel structures in WinDBG in order to hide the EPROCESS 2 \(white\):

![](../../.gitbook/assets/image%20%28317%29.png)

* `ActiveProcessLinks.Flink` in EPROCESS 1 will be pointed to EPROCESS 3 `ActiveProcessLinks.Flink`
* `ActiveProcessLinks.Blink` in EPROCESS 3 will be pointed to EPROCESS 1 `ActiveProcessLinks.Flink`

Kernel memory manipulations will unlink the EPROCESS 2 from the previous node \(EPROCESS 1\) and the next node \(EPROCESS 3\) in the doubly-linked list and, effectively, render it invisible to all userland APIs that retrieve running system processes - exactly like Windows kernel rootkits do it.

## Walkthrough

### Launching Target Process

Let's launch a process that we will try to hide - a notepad.exe in my case:

![](../../.gitbook/assets/image%20%2868%29.png)

In kernel, we can get more information about our `notepad` process like so:

```erlang
kd> !process e14 0
```

Below shows that our notepad's corresponding `EPROCESS` structure is located at `ffffb208f8b304c0`:

![](../../.gitbook/assets/image%20%28470%29.png)

Checking the EPROCESS structure of our notepad:

```erlang
kd> dt _eprocess ffffb208f8b304c0
```

...we can see the `ActiveProcessLinks`, the doubly-linked list, populated with two pointers \(Flink and Blink\):

![](../../.gitbook/assets/image%20%28293%29.png)

We can also read those values with `dt _list_entry ffffb208f8b304c0+2f0` or by dumping two 64-bit long values from `ffffb208f8b304c0+2f0`:

```erlang
kd> dq ffffb208f8b304c0+2f0 L2
ffffb208`f8b307b0  ffffb208`f8d1e7b0 ffffb208`f8b89370
```

### Notepad's Flink and Blink

Let's now figure out the previous and next EPROCESS nodes our notepad.exe is pointing to.

Below shows in two different ways \(1. observing `ActiveProcessLinks` from the EPROCESS structure; 2. reading two 64-bit values from the `EPROCESS+0x2f0`\) that our notepad's:

* FLINK \(green\) is pointing to ``ffffb208`f8d1e7b0`` 
* BLINK \(blue\) is pointing to ``ffffb208`f8b89370``

![](../../.gitbook/assets/image%20%28281%29.png)

For curiosity, we can check the process's image name referenced by the notepad's FLINK at ``ffffb208`f8d1e7b0`` - the next EPROCESS node to our notepad's EPROCESS: 

We need to: 

* find the EPROCESS location by subtracting 0x2f0 from the FLINK ``ffffb208`f8d1e7b0``. This is because FLINK points to `EPROCESS.ActiveProcessLinks` and `ActiveProcessLinks` is located at offset 0x2f0 from the beginning of the EPROCESS location
* add 0x450 since this is the offset of the `ImageFileName` in the EPROCESS structure

```erlang
kd> da ffffb208`f8d1e7b0-2f0+450
```

![](../../.gitbook/assets/image%20%28430%29.png)

Let's do the same for the process referenced by the notepad's BLINK to get the previous EPROCESS node to our notepad's EPROCESS:

```erlang
kd> da ffffb208`f8b89370-2f0+450
```

![](../../.gitbook/assets/image%20%28190%29.png)

Looks like our notepad EPROCESS is surrounded by two svchost EPROCESS nodes.

Continuing, we can get PIDs of those two svchost.exe processes referenced by FLINK and BLINK and they are `0x000009cc` and `0x00001464` respectively as shown below:

```erlang
kd> dd ffffb208`f8d1e7b0-2f0+2e8 L1
ffffb208`f8d1e7a8  000009cc

kd> dd ffffb208`f8b89370-2f0+2e8 L1
ffffb208`f8b89368  00001464

kd> !process 000009cc 0
Searching for Process with Cid == 9cc
PROCESS ffffb208f8d1e4c0
    SessionId: 0  Cid: 09cc    Peb: 44b2cd5000  ParentCid: 025c
    DirBase: 1e5730002  ObjectTable: 00000000  HandleCount:   0.
    Image: svchost.exe

kd> !process 00001464 0
Searching for Process with Cid == 1464
PROCESS ffffb208f8b89080
    SessionId: 0  Cid: 1464    Peb: a260bb6000  ParentCid: 025c
    DirBase: 19071002  ObjectTable: ffffc208ea7e4a80  HandleCount: 141.
    Image: svchost.exe
```

Below shows essentially the same as the above output with some colour-coding: 

![](../../.gitbook/assets/image%20%2813%29.png)

...where highlighted in green is the svchost \(0x09cc\) referenced by notepad's FLINK and in blue is the svchost \(0x1464\) referenced by notepad's BLINK.

### Svchost 9cc Flink and Blink

Let's get the FLINK and BLINK for the svchost.exe \(PID 0x9cc\) and note that ``ffffb208`f8d1e7b0`` is the location of `EPROCESS.ActiveProcessLinks` which will be important later:

```erlang
kd> dq ffffb208f8d1e4c0+2f0 L2
ffffb208`f8d1e7b0  ffffb208`f94ee7b0 ffffb208`f8b307b0

dt _eprocess ffffb208f8d1e4c0
```

Green is FLINK and blue is BLINK:

![](../../.gitbook/assets/image%20%28451%29.png)

### Svchost 1464 Flink and Blink

Let's get FLINK and BLINK for the svchost.exe \(PID 0x1464\) and note that ``ffffb208`f8b89370`` is the location of `EPROCESS.ActiveProcessLinks` which will be important later:

```erlang
kd> dq ffffb208f8b89080+2f0 L2
ffffb208`f8b89370  ffffb208`f8b307b0 ffffb208`f96c97b0

kd> dt _eprocess ffffb208f8b89080
```

Green is FLINK and blue is BLINK:

![](../../.gitbook/assets/image%20%28192%29.png)

### Unlinking the Notepad

We can now summarize the FLINK and BLINK pointers we have for all the processes we are interested in:

| Image | PID | EPROCESS | ActiveProcessLinks | Flink | Blink |
| :--- | :--- | :--- | :--- | :--- | :--- |
| svchost | 0x1464 | ffffb208f8b89080 | ffffb208\`f8b89370 | ffffb208\`f8b307b0 | ffffb208\`f96c97b0 |
| notepad | 0xe14  | ffffb208f8b304c0 | ffffb208\`f8b307b0 | ffffb208\`f8d1e7b0 | ffffb208\`f8b89370 |
| svchost | 0x9cc | ffffb208f8d1e4c0 | ffffb208\`f8d1e7b0 | ffffb208\`f94ee7b0 | ffffb208\`f8b307b0 |

Below are the two kernel modifications we need to perform in order to hide notepad.exe from process listing APIs in the userland:

1. Point svchost's \(0x1464\) FLINK at ``ffffb208`f8b89370`` to svchost's \(0x9cc\) FLINK at ``ffffb208`f8d1e7b0``
2. Point svchost's \(0x9cc\) BLINK at ``ffffb208`f8d1e7b0+8`` \(+8 because LIST\_ENTRY is two fields FLINK/BLINK and are 8 bytes each on x64\) to svchost's \(0x1464\) FLINK at ``ffffb208`f8b89370``

Below visualizes the above outlined steps:

![](../../.gitbook/assets/image%20%28382%29.png)

Let's perform the above mentioned kernel modifications:

```text
kd> eq ffffb208`f8b89370 ffffb208`f8d1e7b0
kd> eq ffffb208`f8d1e7b0+8 ffffb208`f8b89370
```

### Moment of Truth

Once the kernel memory is modified, we can run a `get-process` or `ps notepad` in powershell and observe that notepad.exe has been successfully hidden:

![notepad not seen when &quot;ps notepad&quot; is executed, although notepad is still running in the foreground](../../.gitbook/assets/image%20%28466%29.png)

...although it can still be looked up by its PID in the kernel:

```erlang
!process e14 0
```

![](../../.gitbook/assets/image%20%28365%29.png)

Below is another quick demo showing how notepad.exe disappears from the Windows Task Manager once the kernel memory is tampered and the debugger is resumed. Additionally, `ps notepad` returns nothing, although notepad is visible in the taskbar and underneath the Windows Task Manager:

![](../../.gitbook/assets/hide-process.gif)

{% hint style="info" %}
In the above demo, memory offsets of structures are different due to a system reboot since the initial write up.
{% endhint %}

## Detection

In order to detect unlinked processes exhibited by malware on systems without PatchGuard, explore [`psscan`](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#psscan) and [`psxview`](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Mal#psxview) from Volatility.

## References

{% embed url="https://www.aldeid.com/wiki/LIST\_ENTRY" %}

{% embed url="https://www.hackerearth.com/practice/notes/doubly-linked-list-data-structure-in-c/" %}

