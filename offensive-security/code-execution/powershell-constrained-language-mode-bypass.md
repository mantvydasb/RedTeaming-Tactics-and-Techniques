---
description: Understanding ConstrainedLanguageMode
---

# Powershell Constrained Language Mode ByPass

Constrained Language Mode in short locks down the nice features of Powershell usually required for complex attacks to be carried out.

## Powershell Inside Powershell

For fun - creating another powershell instance inside powershell without actually spawning a new `powershell.exe` process:

![](../../.gitbook/assets/ps-invoke.gif)

## Constrained Language Mode

Enabling constrained language mode, that does not allow powershell execute complex attacks \(i.e. mimikatz\):

```csharp
[Environment]::SetEnvironmentVariable(‘__PSLockdownPolicy‘, ‘4’, ‘Machine‘)
```

Checking constrained language mode is enabled:

```csharp
PS C:\Users\mantvydas> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage
```

![](../../.gitbook/assets/ps-constrained.png)

With `ConstrainedLanguage`, trying to download a file from remote machine, we get `Access Denied`:

![](../../.gitbook/assets/ps-constrained-download-denied.png)

However, if you have access to the system and enough privileges to change environment variables, the lock can be lifted by removing the variable `__PSLockdownPolicy` and re-spawning another powershell instance.

### Powershell Downgrade

If you have the ability to downgrade to Powershell 2.0, this can allow you to bypass the `ConstrainedLanguage`mode. Note how `$ExecutionContext.SessionState.LanguageMode` keeps returning `ConstrainedLangue` in powershell instances that were not launched with `-version Powershell 2` until it does not:

![](../../.gitbook/assets/ps-downgrade.png)

## References

{% embed url="https://blogs.msdn.microsoft.com/powershell/2017/11/02/powershell-constrained-language-mode/" %}

{% embed url="https://www.blackhillsinfosec.com/powershell-without-powershell-how-to-bypass-application-whitelisting-environment-restrictions-av/" %}

{% embed url="https://adsecurity.org/?p=2604" %}

{% embed url="https://pentestn00b.wordpress.com/2017/03/20/simple-bypass-for-powershell-constrained-language-mode/" %}

