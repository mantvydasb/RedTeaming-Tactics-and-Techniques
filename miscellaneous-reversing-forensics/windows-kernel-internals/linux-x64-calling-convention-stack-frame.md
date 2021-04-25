# Linux x64 Calling Convention: Stack Frame

## Code \#1

Below insights are based on the following C program compiled on a 64-bit Linux machine:

```cpp
#include <stdio.h>

int test(int a, int b, int c, int d, int e, int f, int g, int h, int i)
{
    return 1;
}

int main(int argc, char *argv[])
{
    // char buf[1] = {0};
    test(30,31,32,33,34,35,36,37,38);
    return 1;
}

// compile with gcc stack.c -o stack
```

![](../../.gitbook/assets/image%20%28860%29.png)

### Arguments

Below is a screenshot that shows where the 9 arguments `30,31,32,33,34,35,36,37,38` passed to the function `test(int a, int b, int c, int d, int e, int f, int g, int h, int i)` end up in the program's memory \(i.e registers and the stack\):

![](../../.gitbook/assets/image%20%28866%29.png)

Below is a table that complements the above screenshot:

| Argument \# | Location | Variable | Value | Colour |
| :--- | :--- | :--- | :--- | :--- |
| 1 | RDI | a | 30 | Red |
| 2 | RSI | b | 31 | Red |
| 3 | RDX | c | 32 | Red |
| 4 | RCX | d | 33 | Red |
| 5 | R8 | e | 34 | Orange |
| 6 | R9 | f | 35 | Orange |
| 7 | RSP+0x10 | g | 36 | Lime |
| 8 | RSP+0x18 | h | 37 | Lime |
| 9 | RSP+0x20 | i | 38 | Lime |

{% hint style="info" %}
Same applies to arguments that are memory addresses/pointers.
{% endhint %}

### State Inside main\(\)

![](../../.gitbook/assets/image%20%28869%29.png)

Note from the above screenshot:

* Lime - `RDI` contains the the count of arguments our program was launched with \(`argc`\);
* Orange - `RSI` contains the address to an array of arguments our program was run with \(`argv[]`\) and the first one \(`argv[0]`\), as expected, is always the full path to the program itself, which is `/home/kali/labs/stack/stack` in our case.

### State Inside test\(\)

Below inspects what instructions and how they affect the stack and registers once the program is inside the `test()` function:

![](../../.gitbook/assets/image%20%28870%29.png)

Note the following:

* Lime - signifies the `RBP` value on the stack and that it gets pushed to the stack with `push rbp` followed by `mov rbp, esp` instructions at `0x555555555125` and `0x555555555126`;
* Blue - signifies arguments 7, 8, 9 pushed on to the stack with instructions `push 0x26`, `push 0x25`, `push 0x24` respectively at `0x0000555555555153`, `0x0000555555555155` and `0x0000555555555157`;
* Red - `0x000055555555517e` - signifies a return address the program will return to after the `test()` function completes.

![](../../.gitbook/assets/image%20%28862%29.png)

### Code \#2

```cpp
#include <stdio.h>

int test(int a, int b, int c, int d, int e, int f, int g, int h, int i)
{
    return 1;
}

int main(int argc, char *argv[])
{
    char buf[1] = {0};
    test(30,31,32,33,34,35,36,37,38);
    return 1;
}
```



## References

{% embed url="https://revers.engineering/applied-re-the-stack/" %}

{% embed url="https://revers.engineering/applied-re-accelerated-assembly-p1/" %}

