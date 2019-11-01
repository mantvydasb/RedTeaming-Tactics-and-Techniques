---
description: Code Injection
---

# PE Injection: Executing PEs inside Remote Processes

This is a quick lab of a simplified way of injecting an entire portable executabe \(PE\) into another running process. Note that in order to inject more complex PEs, additional DLLs in the target process may need to be loaded and Import Address Table fixed and for this, refer to my other lab [Reflective DLL Injection](reflective-dll-injection.md#resolving-import-address-table).

## Overview

In this lab, I wrote a simple C++ executable that consists of two functions:

* `main` - this is the function that is responsible for injection of the PE image of the running process into a remote/target process
* `InjectionEntryPoint` - this is the function that will get executed by the target process \(notepad in my case\) once it gets injected. 
  * This function will pop a `MessageBox` with a name of the module the code is currently running from. If injection is successful, it should spit out a path of notepad.exe.

High level process of the technique as used in this lab:

1. Parse the currently running image's PE headers and get its `sizeOfImage`
2. Allocate a block of memory \(size of PE image retrieved in step 1\) in the currently running process. Let's call it `localImage`
3. Copy the image of the current process into the newly allocated local memory
4. Allocate new memory block \(size of PE image retrieved in step 1\) in a remote process - the target process we want to inject the currently running PE into. Let's call it `targetImage`
5. Calculate delta between memory addresses `localImage` and `targetImage`
6. Patch the PE you're injecting or, in other words, relocate it/rebase it to `targetImage`. For more information about image relocations, see my other lab [T1093: Process Hollowing and Portable Executable Relocations](process-hollowing-and-pe-image-relocations.md)
7. Write the patched PE into `targetImage` memory location
8. Create remote thread and point it to `InjectionEntryPoint` function inside the PE

## Demo

Below shows how we've injected the PE into the notepad \(PID 11068\) and executed its function `InjectionEntryPoint` which printed out the name of a module the code was running from, proving that the PE injection was succesful:

![](../../.gitbook/assets/pe-injection.gif)

## Code

{% embed url="https://gist.github.com/mantvydasb/229d58d0686cacb7fe52135cf8ee0f1d" %}

## References

{% embed url="https://www.andreafortuna.org/2018/09/24/some-thoughts-about-pe-injection/" %}

{% embed url="https://blog.sevagas.com/PE-injection-explained" %}

{% embed url="https://www.malwaretech.com/2013/11/portable-executable-injection-for.html" %}

