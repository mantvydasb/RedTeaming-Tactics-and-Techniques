---
description: Defense Evasion
---

# T1099: Timestomping

## Execution

Checking original timestamps of the `nc.exe`:

```csharp
.\timestomp.exe .\nc.exe -v
```

![](../../.gitbook/assets/timestomp-original.png)

Forging the file creation date:

```csharp
.\timestomp.exe .\nc.exe -c "Monday 7/25/2005 5:15:55 AM"
```

![](../../.gitbook/assets/timestomp-forged.png)

Checking the `$MFT` for changes - first of, dumping the `$MFT`:

```csharp
.\RawCopy64.exe /FileNamePath:C:\$MFT /OutputName:c:\experiments\mft.dat
```

![](../../.gitbook/assets/timestomp-dump-parse-mft.png)

Let's find the `nc.exe` record and check its timestamps:

```csharp
Import-Csv .\mft.csv -Delimiter "`t" | Where-Object {$_.Filename -eq "nc.exe"}
```

Note how `fnCreateTime` did not get updated:

![](../../.gitbook/assets/timestomp-mft-timestamps.png)

For this reason, it is always a good idea to check both `$STANDARD_INFO` and `$FILE_NAME` times during the investigation to have a better chance at detecting timestomping.

Note that if we moved the nc.exe file to any other folder on the system and re-parsed the $MFT again, the `fnCreateTime` timestamp would inherit the timestamp from `siCreateTime`:

![](../../.gitbook/assets/timestomp-moved.png)

## References

{% embed url="https://www.forensicswiki.org/wiki/Timestomp" %}

{% embed url="https://digital-forensics.sans.org/blog/2010/11/02/digital-forensics-time-stamp-manipulation" %}

{% embed url="https://attack.mitre.org/wiki/Technique/T1099" %}

