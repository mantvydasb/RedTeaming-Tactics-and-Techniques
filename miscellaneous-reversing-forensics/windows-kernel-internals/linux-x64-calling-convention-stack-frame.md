# Linux x64 Calling Convention: Stack Frame

## TL; DR

In 64-bit Linux system, function arguments of type integer/pointers are passed to the callee function in the following way:

* Arguments 1-6 are passed via registers RDI, RSI, RDX, RCX, R8, R9 respectively;
* Arguments 7 and above are pushed on to the stack.

Once inside the callee function:

* Arguments 1-6 are accessed via registers RDI, RSI, RDX, RCX, R8, R9 before they are modified or via  offsets from the RBP register like so: `rbp - $offset`. For example, if the first argument passed to the callee is `int` (4 bytes) and there are no local variables defined in the function, we could access it via `rbp - 0x4`;&#x20;
* It's worth noting, that:
  * if the 1st argument was 8 bytes (for example, `long int`), we'd access it via `rbp - 0x8`;
  * if the callee function had 1 local variable defined that is smaller or equal to 16 bytes, the first argument of type `int` would be accessed via `rbp - (0x10 + 0x4)` or simply `rbp - 0x14`;
  * if the callee function had more than 16 bytes reserved for local variables, we'd access the first argument of type `int` via `rbp - 0x24`, which suggests that with every 16 bytes worth of local variables defined, the first argument is shifted by 0x10 bytes as shown [here](linux-x64-calling-convention-stack-frame.md#accessing-1st-argument);
* Argument 7 can be accessed via `rbp + 0x10`, argument 8 via `rbp + 0x18` and so on.

{% hint style="warning" %}
Conclusions listed above are based on the code sample and screenshots provided in the below sections.
{% endhint %}

## Code

This lab and conclusions are based on the following C program compiled on a 64-bit Linux machine:

{% tabs %}
{% tab title="stack.c" %}
```cpp
#include <stdio.h>

int test(int a, int b, int c, int d, int e, int f, int g, int h, int i)
{
    //int a2 = 0x555577;
    return 1;
}

int main(int argc, char *argv[])
{
    test(0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9);
    return 1;
}

// compile with gcc stack.c -o stack
```
{% endtab %}
{% endtabs %}

## How Arguments Are Passed

Let's now see how arguments are passed from a caller to callee.

Below is a screenshot that shows where the 9 arguments `0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9`  passed to the function `test(int a, int b, int c, int d, int e, int f, int g, int h, int i)` end up in registers and the stack:

![](<../../.gitbook/assets/image (894).png>)

Below is a table that complements the above screenshot and shows where arguments live in registers and on the stack and how they get there:

| Argument # | Location   | Variable | Value | Colour |
| ---------- | ---------- | -------- | ----- | ------ |
| 1          | RDI        | a        | 0x1   | Red    |
| 2          | RSI        | b        | 0x2   | Red    |
| 3          | RDX        | c        | 0x3   | Red    |
| 4          | RCX        | d        | 0x4   | Red    |
| 5          | R8         | e        | 0x5   | Orange |
| 6          | R9         | f        | 0x6   | Orange |
| 7          | RSP + 0x10 | g        | 0x7   | Lime   |
| 8          | RSP + 0x18 | h        | 0x8   | Lime   |
| 9          | RSP + 0x20 | i        | 0x9   | Lime   |

{% hint style="info" %}
Same applies to arguments that are memory addresses/pointers.
{% endhint %}

## Stack Inside test()

Below shows how function's `test` stack frame looks like on a 64-bit platform:

![Stack frame x64 inside the function test()](<../../.gitbook/assets/image (891).png>)

Again, note the following:

* Arguments 1 - 6 are moved through the registers `edi`, `esi`, `edx`, `ecx`, `r8d`, `r9d` (orange);
* Arguments 7 - 9 are pushed to the stack via `push` (blue);

### Accessing the 1st Argument & Local Variables

Until now, our `test()` function did not have any local variables defined, so let's see how the stack changes once we have some variables and how we can access them.

If the callee had a local variable defined, such as `int a1 = 0x555577` (4 bytes, lime) as in our case shown below (lime), we'd access the first argument not via `rbp - 0x4` as it was the case previously when the callee had no local variables, but via `rbp - 0x14` (i.e it shifted by 0x10 bytes, red):

![First argument (red) is now shifted by 0x10 on the stack and can be accessed via rbp - 0x14](<../../.gitbook/assets/image (893).png>)

Based on the above case, the `test()` function stack frame, would now look like this:

![64-bit stack frame with 1 local variable defined inside the callee function](<../../.gitbook/assets/image (890).png>)

{% hint style="warning" %}
Note that the 1st argument, that we previously could access via `rbp - 0x4` has been shifted up by 0x10 bytes and is now accessible via `rbp - 0x14 `whereas the local variable is now at `rbp - 0x4` (where the 1st argument was when the function did not have a local variable defined) followed by 0x10 bytes of padding.
{% endhint %}

Following the same principle as outlined above, if the callee had more than 16 bytes of local variables defined (17 bytes in our case as shown in the below screenshot), we'd now access the first argument via `rbp - 0x24` (i.e another 0x10 bytes shift from `rbp - 0x14`):

![First argument is shifted by 0x10 once again and can be accessed via rbp - 0x24](<../../.gitbook/assets/image (883).png>)

Similarly, if the callee had more than 32 bytes of local variables defined (33 bytes in our case as shown in the below screenshot), we'd now access the first argument via `rbp - 0x34` (i.e yet another 0x10 bytes  shift):

![First argument is shifted by 0x10 once again and can be accessed via rbp - 0x34](<../../.gitbook/assets/image (884).png>)

...and so on.

## State Inside main()

Below captures program's state once inside `main()`:

![RDI and RSI registers inside main() contain argument count and argument values](<../../.gitbook/assets/image (866).png>)

Note from the above screenshot:

* Lime - `RDI` contains the the count of arguments our program was launched with (`argc`);
* Orange - `RSI` contains the address to an array of arguments our program was run with (`argv[]`) and the first one (`argv[0]`), as expected, is always the full path to the program itself, which is `/home/kali/labs/stack/stack` in our case.

Also, if we check what's happening higher up at the stack, we will see that it contains the environment variables the program was started with:

![](<../../.gitbook/assets/image (906).png>)

Combining all the above knowledge, we can get a general view of the stack layout:

![Stack layout for 64-bit program on 64-bit Linux system](<../../.gitbook/assets/image (911).png>)

## References

{% embed url="https://revers.engineering/applied-re-the-stack/" %}

{% embed url="https://revers.engineering/applied-re-accelerated-assembly-p1/" %}
