# Writing a Custom Bootloader

The purpose of this lab is to familiarize with what a bootloader is and how to write a simple "Hello World" type of bootloader and see how to load it using [Qemu](https://www.qemu.org/download/).

{% hint style="info" %}
WIP
{% endhint %}

## Bootloader Overview

Quick facts:

* Bootloader is a special piece of software that is loaded into computer's Random Access Memory \(RAM\) after the BIOS finishes with its Power-On Self Test \(POST\);
* Bootloader's primary purpose is to load the OS kernel
* When BIOS needs to load an OS, it goes through the available devices on the system such as HDDs / CD-ROM / USB / Floppy and checks if any of them are bootable and contain a bootloader by:
  1. Reading in the first 512 bytes \(boot sector\) from the medium and storing them at memory location `0x7c00`
  2. Checking if the last 2 bytes are `0xaa55` - the magic number signifying to the BIOS that it's a Master Boot Record and it's a bootable disk / contains a bootloader;
* Once the bootloader is found, the BIOS transfers code execution to `0x7c00` and the bootloader code gets executed;
* During bootloader execution, the processor operates in 16 bit mode, meaning the bootloader can only use 16 bit registers in its code.

## First Bootloader 

Let's create our first bootable sector that will be 512 bytes in size, using assembly code written in [NASM](https://www.nasm.us/):

![](../../.gitbook/assets/image%20%28773%29.png)

Key aspects of the above code:

1. Line 2 - instructs NASM to generate code for CPU operating in 16 bit mode
2. Lines 5-6 - the bootloader's code, which is simply an infinite loop!
3. Line 11 - `times 510 - ($-$$) db 0` - instructs NASM to fill the space between instruction `jmp loop` \(2 bytes in size\) and the last two bytes `0xaa55` \(line 13, signifies the magic bytes of the boot sector\) with `0x00` 508 null bytes, to make sure that the boot sector is exactly 512 bytes in size.

NASM knows it needs to fill the binary with 508 null bytes?

* $ - address of the current instruction - `jmp loop` \(2 bytes\)
* $$ - address of the start of the code section - 0x00 when the binary is on the disk

Given the above, `times 510 - ($-$$) db 0` reads as - pad the binary with 00 bytes 508 times: 510 - \(2-0\) = 508. Visually, the booloader binary, once compiled, should look like this:

![](../../.gitbook/assets/image%20%28765%29.png)

Again, note that the total size of the bootloader is 512 bytes:

* 2 bytes for instructions jmp loop
* 508 NULL bytes
* 2 magic bytes

If we compile our following bootloader code:

{% code title="bootloader-dev.asm" %}
```csharp
; Instruct NASM to generate code that is to be run on CPU that is running in 16 bit mode
bits 16

; Infinite loop
loop:
    jmp loop

; Fill remaining space of the 512 bytes minus our instrunctions, with 00 bytes
; $ - address of the current instruction
; $$ - address of the start of the image .text section we're executing this code in
times 510 - ($-$$) db 0
; Bootloader magic number
dw 0xaa55
```
{% endcode %}

with NASM like so:

```text
nasm -f bin bootloader-dev.asm -o bootloader.bin
```

..and dump bytes of `bootload.bin`, we can confirm that our bootloader file structure is as we intended - 2 bytes for the `jmp loop` instruction \(`eb fe`\) at offset 0, followed by 510 null bytes and two magic bytes `0x55aa` at the end, taking up a total of 512 bytes:

![](../../.gitbook/assets/image%20%28767%29.png)

## Emulate the Bootloader

We can now check if we can make our bootloader execute using qemu like so:

```text
qemu-system-x86_64.exe C:\labs\bootloader\bootloader.bin
```

Below shows how our bootloader is loaded from the hard disk and goes into an infinite loop:

![](../../.gitbook/assets/emulate-bootloader.gif)

## Bootloader Location in Memory

As mentioned previously, BIOS reads in the boot sector \(512 bytes\), containing the bootloader, from a bootable device into computer memory. It's known that the bootloader is stored at the memory location `0x7c00` as shown in the below graphic:

![Source: https://www.cs.bham.ac.uk/~exr/lectures/opsys/10\_11/lectures/os-dev.pdf](../../.gitbook/assets/image%20%28769%29.png)

We can confirm that the bootloader code is placed at `0x7c00` by performing two simple tests.

### Test 1

Let's take the below code:

{% code title="bootloader-x.asm" %}
```csharp
bits 16

; Define a label X that is a memory offset of the start of our code.
; It points to a character B.
x:
    db "B"

; Move offset of x to bx
mov bx, x

; Add 0x7c00 to bx - it's universally known that BIOS loads bootloaders to this location.
; add bx, 0x7c00

; Move contents of bx to al
mov al, [bx]

; Prepare interrupt to print a character in TTY mode and issue the interrupt.
mov ah, 0x0e
int 0x10                                                

times 510 - ($-$$) db 0
dw 0xaa55
```
{% endcode %}

{% hint style="info" %}
Note the line 12 with instrunctions `add bx, 0x7c00` is commented out - we will uncomment it in Test 2 and confirm that the bootloader is indeed loaded at `0x7c00`.
{% endhint %}

...which does the following

* Creates a label `X` that is a memory offset to the character `B` from the start of computer **memory and not from the start of our code location**.
* Populate `bx` with the offset of the label `x` \(0 in our case\) with the aim to make bx point to the character `B`.
* Dereference `bx` \(take the value from the memory address pointed to by the `bx`\) and put it in `al`
* Issue a BIOS interrupt and attempt to print the value of `al` to the screen, which one could expect to be the character `B`, but as we will soon see, it will not be.

{% hint style="warning" %}
**Important to remember**  
The CPU treats assembly labels \(like our label `x`\) as offsets from the start of computer memory, rather than offsets from the start of the location where our code was loaded to. 
{% endhint %}

We can compile the above code with `nasm -f bin .\bootloader-x.asm -o bootloader.bin` and launch it with `qemu-system-x86_64.exe C:\labs\bootloader\bootloader.bin` and see the result:

![B character not displayed](../../.gitbook/assets/image%20%28764%29.png)

Note how instead of seeing the character `B`, we actually see some random character `S`, which suggests are reading the wrong memory location.

For reference, this is a snippet of the hex dump of our bootloader we've just compiled:

![](../../.gitbook/assets/image%20%28770%29.png)

Note that the very first byte \(offset 0 while it's on disk\) is `42`, which is a letter `B` in ascii - the character our label `x` is pointing to, which we want to print to the screen.

### Test 2

Test 1 confirmed that we do not know where the character `B` is located in memory. Let's now take the same code we used in the Test 1 and uncomment the instruction `add bx, 0x7c00` in line 12, which adds `0x7c00` to our label `x`:

{% code title="bootloader-x.asm" %}
```cpp
bits 16

; Define a label X that is a memory offset of the start of our code.
; It points to a character B.
x:
    db "B"

; Move offset of x to bx
mov bx, x

; Add 0x7c00 to bx - it's universally known that BIOS loads bootloaders to this location.
add bx, 0x7c00

; Move contents of bx to al
mov al, [bx]

; Prepare interrupt to print a character in TTY mode and issue the interrupt.
mov ah, 0x0e
int 0x10                                                

times 510 - ($-$$) db 0
dw 0xaa55
```
{% endcode %}

...and re-compile the above code with `nasm -f bin .\bootloader-x.asm -o bootloader.bin` and launch it with `qemu-system-x86_64.exe C:\labs\bootloader\bootloader.bin`:

![B character is now displayed](../../.gitbook/assets/image%20%28772%29.png)

...we can now see that the character `B` is finally printed to the screen, which confirms that our bootlaoder code is located at memory location `0x7c00`.

Indeed, if we inspect the qemu process memory, that has our bootloader loaded and running, search for the bytes `42bb 0000 8a07 b40e cd10 0000` \(the starting bytes of our bootloader, as seen in the hex dump on the right hand side highlighted in lime\), we can see that our bootloader resides at offset 44D**07C00**:

![Our bootloader in memory \(left\) and on disk \(right\)](../../.gitbook/assets/image%20%28775%29.png)

Note that in the above screenshot, the character `B` ****\(in red\) is our character `B` that we print to the screen, that sits at the very beginning our bootloader - at offsets `0x0` in a raw binary on the disk and at the offset `0x07c00` when it's loaded to memory by the BIOS as a bootloader, or in the case of our emulation with qemu - at offset `0x44d07c00`.

## References

[https://www.cs.bham.ac.uk/~exr/lectures/opsys/10\_11/lectures/os-dev.pdf](https://www.cs.bham.ac.uk/~exr/lectures/opsys/10_11/lectures/os-dev.pdf)

{% embed url="https://manybutfinite.com/post/how-computers-boot-up/" %}

{% embed url="https://www.ionos.com/digitalguide/server/configuration/what-is-a-bootloader/" %}

{% embed url="https://github.com/cfenollosa/os-tutorial" %}

{% embed url="http://3zanders.co.uk/2017/10/13/writing-a-bootloader/" %}

