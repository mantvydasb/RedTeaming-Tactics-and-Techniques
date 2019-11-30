# Executing Shellcode with Inline Assembly in C/C++

It's possible to execute shellcode inline in a C/C++ program. The reason why it's good to have this technique in your arsenal is because it does not require you to allocate new `RWX` memory to copy your shellcode over to by using `VirtualAlloc` API which is heavily monitored by EDRs and can get you caught. Instead, the code will get embedded into the PE's `.TEXT` section which is executable by default as this is where the rest of your application's code resides.

## Execution

Install mingw - I'm doing it via chocolatey pacakge manager:

```csharp
choco install mingw
```

Create a simple C program that includes the shellcode. In my case, I'm simply adding 4 NOP instructions and prior to that, I am printing out the string `spotless`, so I can easily identify the shellcode location when debugging the program:

{% code title="inline-shellcode.c" %}
```cpp
#include <Windows.h>
#include <stdio.h>

int main() {
	printf("spotless");
    asm(".byte 0x90,0x90,0x90,0x90\n\t"
		"ret\n\t");
	return 0;
}
```
{% endcode %}

Let's compile and link the code:

```csharp
gcc -c .\inline-shellcode.c -o main.o; g++.exe .\main.o -o .\main.exe
```

Debugging the code via xdbg, we can see where the string `spotless` is going to be printed out and straight after it, we have the 4 NOP instructions:

![](../../.gitbook/assets/image%20%28243%29.png)

## References

{% embed url="https://github.com/Mr-Un1k0d3r/Shellcoding" %}

