# AWS Accounts, Users, Groups, Roles, Policies

Below is a graphical representation of the key components of Identity Access Mangement in AWS:

![](../../.gitbook/assets/image%20%28712%29.png)

* Organization / root / management account can have multiple other accounts
* An account can have Users, Groups, Roles and Policies
* Users can be members of Groups and Groups can contain Users
* Role is a secure way to grant termporary permissions to trusted entities:
  * Another AWS account \(yours or 3rd party's\)
  * AWS service
  * Web Identity
  * SAML Federation
  * All of the above mentioned trusted entities can assume a Role given they have the permission `sts:AssumeRole`
* Policies signify what can/can't be done with resources \(i.e EC2 `instance`, `image`, `network interface`, `security group`, etc.\). Policies are defined as JSON objects
* Level of access that a User, Group or a Role \(identities\) has on certain resources, is defined by Policies that are attached to said identities

