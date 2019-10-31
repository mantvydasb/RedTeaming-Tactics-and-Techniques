---
description: Code Injection
---

# Injecting PE to other Processes

This is a quick note that shows how to inject an image of a running Portable Executable \(PE\) into another running process.

## Overview

High level process of the technique used in the lab:

1. Parse the currently running image's PE headers and get its `sizeOfImage`
2. Allocate a block of memory \(size of PE image retrieved in step 1\) in the currently running process. Let's call it `localImage`
3. Copy the image of the current process into the newly allocated local memory
4. Allocate new memory block \(size of PE image retrieved in step 1\) in a remote process - the target process we want to inject the currently running PE into. Let's call it `targetImage`
5. Calculate delta between `localImage` and `targetImage`
6. Patch the PE you're injecting or in other words - relocate/rebase it to `targetimage`
7. Write the patched PE into `targetImage` memory location
8. Create remote thread and point it to a function inside the PE

![](../../.gitbook/assets/image%20%2843%29.png)



## Demo

Below shows how we've injected the PE and executed a function `InjectionEntryPoint` it contains, inside the notepad.exe process with PID 11068:

![](../../.gitbook/assets/pe-injection.gif)

## Code

{% embed url="https://gist.github.com/mantvydasb/229d58d0686cacb7fe52135cf8ee0f1d" %}

## References

{% embed url="https://www.andreafortuna.org/2018/09/24/some-thoughts-about-pe-injection/" %}

{% embed url="https://blog.sevagas.com/PE-injection-explained" %}

{% embed url="https://www.malwaretech.com/2013/11/portable-executable-injection-for.html" %}

