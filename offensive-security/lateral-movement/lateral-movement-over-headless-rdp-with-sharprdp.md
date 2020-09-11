# Lateral Movement over headless RDP with SharpRDP

Executing commands on a remote host is possible by using a headless \(non-GUI\) RDP lateral movement technique brought by a tool called [SharpRDP](https://posts.specterops.io/revisiting-remote-desktop-lateral-movement-8fb905cb46c3?gi=fe80458d82a5).

## Execution

Executing a binary on a remote machine dc01 from a compromised system with offense\administrator credentials:

```text
SharpRDP.exe computername=dc01 command=calc username=offense\administrator password=123456
```

![](../../.gitbook/assets/image%20%2899%29.png)

## Observations

Defenders may want to look for mstscax.dll module being loaded by suspicious binaries on a compromised host from which SharpRDP is being executed:

![](../../.gitbook/assets/image%20%28360%29.png)

Also, weird binaries making connections to port 3389:

![](../../.gitbook/assets/image%20%2830%29.png)

## References

{% embed url="https://posts.specterops.io/revisiting-remote-desktop-lateral-movement-8fb905cb46c3?gi=fe80458d82a5" %}



