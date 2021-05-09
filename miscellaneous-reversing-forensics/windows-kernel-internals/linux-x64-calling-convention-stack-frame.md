# Linux x64 Calling Convention: Stack Frame

## TL; DR

In 64-bit Linux system, arguments of type integer/pointers are passed to the callee in the following way:

* Arguments 1-6 are passed via registers RDI, RSI, RDX, RCX, R8, R9 respectively;
* Arguments 7 and above are pushed on to the stack.

Once inside the callee function:

* Arguments 1-6 are accessed via registers RDI, RSI, RDX, RCX, R8, R9 before they are modified or via  offsets from the RBP register like so: `rbp - $offset`. For example, if the first argument passed to the callee is `int` \(4 bytes\), we could access it via `rbp - 0x4`. 
* It's worth noting, that:
  * if the 1st argument was 8 bytes \(for example, `long int`\), we'd access it via `rbp - 0x8`;
  * if the callee function had 1 local variable defined that is smaller or equal to 16 bytes, the first argument of type `int` would be accessed via `rbp - (0x10 + 0x4)` or simply `rbp - 0x14`;
  * if the callee function had more than 16 bytes reserved for local variables, we'd access the first argument of type `int` via `rbp - 0x24`, which suggests that with every 16 bytes worth of local variables defined, the first argument is shifted by 0x10 bytes as shown [here](linux-x64-calling-convention-stack-frame.md#accessing-1st-argument).
* Argument 7 can be accessed via `rbp + 0x10`, argument 8 via `rbp + 0x18` and so on.

{% hint style="warning" %}
Conclusions listed above are based on the code sample and screenshots provided in the below sections.
{% endhint %}

## Code

This lab and conclusions are based on the following C program compiled on a 64-bit Linux machine:

```cpp
#include <stdio.h>

int test(int a, int b, int c, int d, int e, int f, int g, int h, int i)
{
    return 1;
}

int main(int argc, char *argv[])
{
    // char buf[1] = {0};
    test(30, 31, 32, 33, 34, 35, 36, 37, 38);
    return 1;
}

// compile with gcc stack.c -o stack
```

## How Arguments Are Passed

Let's now see how arguments are passed from caller to the callee.

Below is a screenshot that shows where the 9 arguments `30, 31, 32, 33, 34, 35, 36, 37, 38` passed to the function `test(int a, int b, int c, int d, int e, int f, int g, int h, int i)` end up in registers and the stack:

![](../../.gitbook/assets/image%20%28866%29.png)

Below is a table that complements the above screenshot and shows where arguments live in registers and on the stack:

| Argument \# | Location | Variable | Value | Colour |
| :--- | :--- | :--- | :--- | :--- |
| 1 | RDI | a | 30 | Red |
| 2 | RSI | b | 31 | Red |
| 3 | RDX | c | 32 | Red |
| 4 | RCX | d | 33 | Red |
| 5 | R8 | e | 34 | Orange |
| 6 | R9 | f | 35 | Orange |
| 7 | RSP + 0x10 | g | 36 | Lime |
| 8 | RSP + 0x18 | h | 37 | Lime |
| 9 | RSP + 0x20 | i | 38 | Lime |

{% hint style="info" %}
Same applies to arguments that are memory addresses/pointers.
{% endhint %}

## Stack Inside test\(\)

Below shows how function's `test` stack frame looks like on a 64-bit platform:

![Stack frame x64 inside the function test\(\)](../../.gitbook/assets/image%20%28884%29.png)

Note from the above screenshot, we can see that `0x000055555555517e` is a return address to the `main` function, as shown below:

![After test\(\) call at 0x0000555555555179 completes, the program will continue at 0x000055555555517e](../../.gitbook/assets/image%20%28876%29.png)

### Accessing the 1st Argument

Until now, our `test()` function did not have any local variables defined, so let's see how the stack changes once we have some variables and how we can reference them from the stack.

If the callee had a local variable defined, such as `a1 = 0x555577` as in our case shown below, we'd access the first argument not via `rbp - 0x4` as it was the case previously when the callee had no local variables, but via `rbp - 0x14`:

![First argument is now shifted by 0x10 on the stack and can be accessed via rbp - 0x14](../../.gitbook/assets/image%20%28887%29.png)

Based on the above case, our stack frame would now look like this:

{% hint style="warning" %}
Note that the local variable is now at `rbp - 0x4` , followed by 0x10 bytes of padding and the 1st argument is now at `rbp - 0x14`.
{% endhint %}

![64-bit stack frame with 1 local variable defined inside the callee function](../../.gitbook/assets/image%20%28878%29.png)

Following the same principle as outlined above, if the callee had more than 16 bytes of local variables defined \(17 bytes in our case as shown in the below screenshot\), we'd now access the first argument via `rbp - 0x24`:

![First argument is shifted by 0x10 once again and can be accessed via rbp - 0x24](../../.gitbook/assets/image%20%28877%29.png)

Similarly, if the callee had more than 32 bytes of local variables defined \(33 bytes in our case as shown in the below screenshot\), we'd now access the first argument via `rbp - 0x34`:

![First argument is shifted by 0x10 once again and can be accessed via rbp - 0x34](../../.gitbook/assets/image%20%28881%29.png)

...and so on...

## State Inside main\(\)

Below captures what the program's state is once we break inside `main()`:

![RDI and RSI registers inside main\(\) contain argument count and arguments themselves](../../.gitbook/assets/image%20%28869%29.png)

Note from the above screenshot:

* Lime - `RDI` contains the the count of arguments our program was launched with \(`argc`\);
* Orange - `RSI` contains the address to an array of arguments our program was run with \(`argv[]`\) and the first one \(`argv[0]`\), as expected, is always the full path to the program itself, which is `/home/kali/labs/stack/stack` in our case.

## References

{% embed url="https://revers.engineering/applied-re-the-stack/" %}

{% embed url="https://revers.engineering/applied-re-accelerated-assembly-p1/" %}

