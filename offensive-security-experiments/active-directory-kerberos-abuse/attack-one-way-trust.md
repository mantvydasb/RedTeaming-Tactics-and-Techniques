# Attack one-way trusted domain/forest (Trust account attack)
If an attacker has administrative access to FORESTB which trusts FORESTA, the attacker can obtain the credentials for a _trust account_ located in FORESTA. This account is a member of Domain Users in FORESTA through its Primary Group. As we see too often, Domain Users membership is all that is necessary to identify and use other techniques and attack paths to become Domain Admin.

![](<https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/61a0233f-edd8-40b6-b6ae-8592a29875bd/Picture3.png>)

This technique is not limited to forest trust but works over any domain/forest one-way trust in the direction trusting -> trusted. 

The trust protections (SID filtering, disabled SID history, and disabled TGT delegation) do not mitigate the technique.

[Read more](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)
