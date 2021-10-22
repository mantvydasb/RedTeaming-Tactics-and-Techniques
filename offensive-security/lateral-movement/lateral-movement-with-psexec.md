# Lateral Movement with Psexec

A very old and noisy lateral movement technique can be performed using psexec by SysInternals.

## Execution

Let's connect from workstation `ws01` to the domain controller `dc01` with domain administractor credentials:

{% code title="attacker@victim" %}
```
.\PsExec.exe -u administrator -p 123456 \\dc01 cmd
```
{% endcode %}

![](<../../.gitbook/assets/Annotation 2019-05-20 210729.png>)

## Observations

The technique is noisy for at least a couple of reasons. Upon code execution, these are some well known artefacts that are left behind which will most likely get you flagged in an environment where SOC is present.

A `psexesvc` service gets created on the remote system and below shows the process ancestry of your command shell:

![](<../../.gitbook/assets/Annotation 2019-05-20 211216.png>)

Proving that `psexec` is actually running as a service:

![](<../../.gitbook/assets/Annotation 2019-05-20 211401.png>)

![](<../../.gitbook/assets/Annotation 2019-05-20 211654 (1).png>)

Additionally, there is quite a bit of SMB network traffic generated when connecting to a remote machine which could be signatured:

![](<../../.gitbook/assets/Annotation 2019-05-20 212123.png>)
