---
description: Persistence
---

# T1136: Create Account

## Execution

{% code title="attacker@victim" %}
```bash
net user test test123 /add /domain
```
{% endcode %}

## Observations

![commandline arguments](../../.gitbook/assets/account-add.png)

There is a whole range of interesting events that could be monitored related to new account creation:

![](../../.gitbook/assets/account-events.png)

Details for the newly added account are logged as event `4720` :

![](../../.gitbook/assets/account-created.png)

## References

{% embed url="https://attack.mitre.org/wiki/Technique/T1136" %}



