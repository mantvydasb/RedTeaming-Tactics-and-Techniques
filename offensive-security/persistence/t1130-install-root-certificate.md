---
description: Defense Evasion
---

# T1130: Installing Root Certificate

## Execution

Adding a certificate with a native windows binary:

{% code title="attacker@victim" %}
```csharp
certutil.exe -addstore -f -user Root C:\Users\spot\Downloads\certnew.cer
```
{% endcode %}

![](../../.gitbook/assets/certs-certutil.png)

Checking to see the certificate got installed:

![](../../.gitbook/assets/certs-installed.png)

Adding the certificate with powershell:

{% code title="attacker@victim" %}
```csharp
Import-Certificate -FilePath C:\Users\spot\Downloads\certnew.cer -CertStoreLocation Cert:\CurrentUser\Root\
```
{% endcode %}

![](../../.gitbook/assets/certs-add-with-ps.png)

## Observations

Advanced poweshell logging to the rescue:

![](../../.gitbook/assets/certs-ps-logging.png)

Commandline logging:

![](../../.gitbook/assets/certs-logs.png)

The CAs get installed to:

```csharp
Computer\HKEY_CURRENT_USER\Software\Microsoft\SystemCertificates\Root\Certificates\C6B22A75B0633E76C9F21A81F2EE6E991F5C94AE
```

..so it is worth monitoring registry changes there:

![](../../.gitbook/assets/certs-registry.png)

## References

{% embed url="https://attack.mitre.org/wiki/Technique/T1130" %}

