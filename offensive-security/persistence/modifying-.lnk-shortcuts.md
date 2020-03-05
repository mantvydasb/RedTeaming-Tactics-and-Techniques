# Modifying .lnk Shortcuts

This is a quick lab showing how .lnk \(shortcut files\) can be used for persistence.

## Execution

Say, there's a shortcut on the compromised system for a program HxD64 as shown below:

![](../../.gitbook/assets/image%20%28343%29.png)

. That shortcut can be hijacked and used for persistence. Let's change the shortcut's target to this simple powershell:

```csharp
powershell.exe -c "invoke-item \\VBOXSVR\Tools\HxD\HxD64.exe; invoke-item c:\windows\system32\calc.exe"
```

It will launch the HxD64, but will also launch a program of our choice - a calc.exe in this case. Notice how the shortcut icon changed to powershell - that is expected:

![](../../.gitbook/assets/image%20%28479%29.png)

We can change it back by clicking "Change Icon" and specifying the original .exe of HxD64.exe:

![](../../.gitbook/assets/image%20%28219%29.png)

The original icon is now back:

![](../../.gitbook/assets/image%20%28193%29.png)

## Demo

Below shows the hijack demo in action:

![](../../.gitbook/assets/lnk-hijacking.gif)

In the above gif, we can see the black cmd prompt for a brief moment, however, it can be easily be hidden by changing the `Run` option of the shortcut to `Minimized`:

![](../../.gitbook/assets/image%20%28336%29.png)

Running the demo again with the `Run: Minimized` shows the black prompt went away:

![](../../.gitbook/assets/lnk-hijacking-minimized.gif)

{% hint style="warning" %}
Note that hovering the shortcut reveals that the program to be launched is the powershell.
{% endhint %}

## Reference

{% embed url="https://attack.mitre.org/techniques/T1023/" %}

