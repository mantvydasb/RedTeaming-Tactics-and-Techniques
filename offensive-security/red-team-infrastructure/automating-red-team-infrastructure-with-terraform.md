# Automating Red Team Infrastructure with Terraform

## Context

The purpose of this lab was to get my hands dirty while building a simple, resilient and easily disposable red team infrastructure. Additionally, I wanted to play around with the the concept of `Infrastructure as a Code`, so I chose to tinker with a tool I have been hearing about for some time now - Terraform**.**

## **Credits**

Automated red teaming infrastructure is not a new concept - quite the opposite - I drew my inspiration from the great work of [@\_RastaMouse](https://twitter.com/_RastaMouse) [where](https://rastamouse.me/2017/08/automated-red-team-infrastructure-deployment-with-terraform-part-1/) he explained his process of building an automated red team environment. He based it off of the great [wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki) by [Steve Borosh](https://twitter.com/424f424f) and [Jeff Dimmock](https://twitter.com/bluscreenofjeff) - which is exactly the resource I used when labbing about the below:

{% page-ref page="./" %}

...as well as this exercise.

## **Infrastructure Overview**

Below is a high level diagram showing the infrastructure that I built for this lab - it can be and usually is much more built out, but the principle remains the same - redirectors are placed in front of each server to make the infrastructure more resilient to discovery that enables operators to quickly replace the burned servers with new ones:

![](../../.gitbook/assets/screenshot-from-2019-01-26-17-45-04%20%281%29.png)

* There are 6 servers in total
* 3 servers \(phishing, payload and c2\) are considered the long term servers - we do not want our friendly blue teams to discover those
* 3 redirectors \(smtp relay, payload redirector and c2 redirector\) - these are the servers that sit in front of our long term servers and act as proxies. It is assumed that these servers will be detected and burned during an engagement. This is where the automation piece of Terraform comes in - since the our environment's state is defined in Terraform configuration files, we can rebuild those burned servers in almost no time and the operation can continue without bigger interruptions.

## Configuring Infrastructure

### Service Providers

My test red team infrasture is built by leveraging the following services and providers:

* DigitalOcean Droplets for all the servers and redirectors
* DigitalOcean DNS management for the smtp relay \(phishing redirector\) - mostly because we need the ability to set a `PTR` DNS record for our smtp relay in order to reduce chances of our phishing email being classified as spam by target users' mail gateways
* CloudFlare DNS management for controlling DNS records for any other domains that point to our long-term servers

Note however, you could build your servers using Amazon AWS or other popular VPS provider as long as it is supported by [Terraform](https://www.terraform.io/docs/providers/). Same applies to the DNS management piece. I used DigitalOcean and CloudFlare because I already had accounts and I like them ¯\\_\(ツ\)\_/¯

### File Structure

My red team infrastructure is defined by terraform state configuration files that are currently organized in the following way:

![](../../.gitbook/assets/screenshot-from-2019-01-26-18-13-38%20%281%29.png)

I think the file names are self explanatory, but below gives additional info on some of the config files:

* `Configs` folder - all the config files that were too big or inconvenient to modify during Droplet creation with Terraform's provisioners. It includes configs for payload redirector \(apache: `.htaccess`, `apache2.conf`\), smtp redirector \(postfix: `header_checks` - for stripping out email headers of the originating smtp server, `master.cf` - general postfix config for TLS and opendkim, `opendkim.conf` - configuring DKIM integration with postfix\)
* providers - required to build the infrastructure such as DigitalOcean and CloudFlare in my case
* variables - stores API keys and similar data used across different terraform state files
* sshkeys - stores ssh keys that our servers and redirectors will accept logons from
* dns - defines DNS records and specify how our servers and redirectors can be accessed
* firewalls - define access rules - who can access which server
* outputs - a file that prints out key IP addresses and domain names of the built infrastructure

Other key points on a couple of the files are outlined below.

### Variables

Variables.tf stores things like API tokens, domain names for redirectors and c2s, operator IPs that are used in firewall rules \(i.e only allow incoming connections to team server or GoPhish from an operator owned IP\):

![](../../.gitbook/assets/screenshot-from-2019-01-27-16-57-04%20%281%29.png)

Additionally, `variables.tf` contains link to a password protected Cobalt Strike zip archive and the password itself:

![URL to a password protected Cobalt Strike zip](../../.gitbook/assets/screenshot-from-2019-01-29-22-32-07.png)

![variables.tf showing my fake and misspelled password](../../.gitbook/assets/screenshot-from-2019-01-27-17-01-52.png)

### C2

For this lab, I chose Cobalt Strike as my C2 server. 

Below is the `remote-exec` Terraform provisioner for C2 server that downloads CS zip, unzips it with a given CS password and creates a cron job to make sure the C2 server is started once the server boots up:

![](../../.gitbook/assets/screenshot-from-2019-01-29-22-31-08.png)

### C2 Redirector

I use a `socat` to simply redirect all incoming traffic on port 80 and 443 to the main HTTP C2 server running Cobalt Strike team server:

![](../../.gitbook/assets/screenshot-from-2019-01-27-17-09-17.png)

### Testing C2 and C2 Redirector

It's easy to test if your C2 and its redirectors work as expected.

Note below - a couple of FQDNs that were printed out by Terraform when outputs.tf file was executed: `static.redteam.me` and `ads.redteam.me` both pointing to `159.203.122.243` - this is the C2 redirector IP - any traffic on port 80 and 443 will be redirected to the main C2 server, which is hosted on `68.183.150.191` as shown in the second image below:

![C2 redirector IPs](../../.gitbook/assets/screenshot-from-2019-02-01-12-00-31.png)

![C2 teamserver IPs](../../.gitbook/assets/screenshot-from-2019-02-01-12-00-22.png)

Below gif shows the test in action and the steps are as follows:

1. Cobalt Strike is launched and connected to the main C2 server hosted on 68.183.150.191 - it can be reached via `css.ired.team`
2. a new listener on port 443 is created on the C2 host 68.183.150.191
3. beacon hostsname are set to two subdomains on the C2 redirector - `static.redteam.me` and `ads.redteam.me`
4. stageless beacon is generated and executed on the target system via SMB
5. beacon calls back to `*.redteam.me` which redirects traffic to the C2 teamserver on 68.183.150.191 and we see a CS session popup:

![Cobalt Strike C2 &amp; C2 redirector test](../../.gitbook/assets/peek-2019-02-01-12-30.gif)

Below is a screengrab of the tcpdump on C2 server which shows that the redirector IP \(organge, 159.203.122.243\) has initiated the connection to the C2 \(blue, 68.183.150.191\):

![Successful C2 traffic redirection](../../.gitbook/assets/screenshot-from-2019-02-01-12-41-44.png)

### Phishing

My phishing server is running GoPhish framework, which I labbed about here:

{% page-ref page="../initial-access/phishing-with-gophish-and-digitalocean.md" %}

![](../../.gitbook/assets/screenshot-from-2019-01-27-17-10-47.png)

The GoPhish is set to listen on port 3333 which I expose to the internet, but only allow access for the operator using DigitalOcean firewalls:

![](../../.gitbook/assets/screenshot-from-2019-01-27-17-14-49.png)

Again - `var.operator-ip` is set in `variables.tf`

### Phishing Redirector

This was the most time consuming piece to set up. It is a known fact that setting up SMTP servers usually is a huge pain. Automating the red team infrastructure is worth purely because of the fact that you will not ever need to rebuild the SMTP server from scratch once it gets burned during the engagement.

The pain for this piece originated from setting up the smtp relay, since there were a number of moving parts to it:

* setting up SPF records
* setting up DKIM
* setting up encryption
* configuring postfix as a relay
* sanitizing email headers to obfuscate the originating email server \(the phishing server\)

### Testing Phishing Redirector

Once the infrastucture has been stood up, phishing redirector's \(smtp relay\) DNS zone should have the spf, dkim and dmarc records, similarly to those seen here:

![](../../.gitbook/assets/screenshot-from-2019-01-29-21-58-25.png)

Once DNS records are done, we can send a quick test email to gmail from the actual phishing server through the relay server and see if spf, dkim and dmarc checks `PASS`, which we can see below they did in our case, suggesting phishing/smtp relay is setup correctly:

{% code title="attacker@kali" %}
```bash
telnet redteam.me 25
helo redteam.me
mail from: olasenor@redteam.me
rcpt to: mantvydo@gmail.com
data
to: Mantvydas Baranauskas <mantvydo@gmail.com>
from: Ola Senor <olasenor@redteam.me>
subject: daily report

Hey Mantvydas,
As you were requesting last week - attaching as promised the documents needed to keep the project going forward.
.
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-01-29-22-03-50.png)

{% file src="../../.gitbook/assets/daily-report.eml" caption="Daily report.eml" %}

### Payload Redirector

Payload redirector server is built on apache2 `mod_rewrite` and `proxy` modules. `Mod_rewrite` module allows us to write fine-grained URL rewriting rules and proxy victim's HTTP requests to appropriate payloads as the operator deems appropriate.

#### .htaccess

Below is an .htaccess file that instructs apache, or to be precise `mod_rewrite` module, on when, where and how \(i.e proxy or redirect\) to rewrite incoming HTTP requests:

{% code title=".htaccess" %}
```typescript
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} "android|blackberry|googlebot-mobile|iemobile|ipad|iphone|ipod|opera mobile|palmos|webos" [NC]
RewriteRule ^.*$ http://payloadURLForMobiles/login [P]
RewriteRule ^.*$ http://payloadURLForOtherClients/%{REQUEST_URI} [P]
```
{% endcode %}

Breakdown of the file:

* Line 2 essentially says: hey, apache, if you see an incoming http request with a user agent that contains any of the words "android, blackberry, ..." etc, move to line 3
* Line 3 instructs apache to proxy \(\[P\]**\)** the http request to `http://payloadURLForMobiles/login`. If condition in line 2 fails, move to line 4
* If condition in line 2 fails, the http request gets proxied to `http://payloadURLForOtherClients/%{REQUEST_URI}` where `REQUEST_URI` is the part of the http request that was appended after the domain name - i.e someDomain.com/?thisIsTheRequestUri=true

Below screenshot should illustrate the above concept:

1. green highlight - we used curl \(and its default UA\), which according to the .htaccess file, should have redirected us to `payloadURLForOtherClients` -  which we see it attempted to, but of course failed since it's a test and a non-resolvable host is specified
2. pink - we curl'ed the payload redirector again, but this time with a forged UA, masquerading the http request as if it was coming from an iphone - we can see that apache correctly attempted to proxy the request through to the `payloadURLForMobiles` host:

![](../../.gitbook/assets/screenshot-from-2019-01-28-21-34-44.png)

### Outputs

`Outputs.tf` contains key server DNS names and their IP addresses for operator's reference:

![](../../.gitbook/assets/screenshot-from-2019-01-28-21-50-22.png)

Also, note the last highlighted bit - an instruction for an operator to execute a `./finalize.sh` command from the working directory. It will install `LetsEncrypt` certificates on the smtp relay server and also print out the DKIM DNS TXT record that needs to be added to the DigitalOcean's DNS records for the smtp relay domain:

![](../../.gitbook/assets/screenshot-from-2019-01-28-21-49-44.png)

The DNS record `mail._domainkey` placeholder with a dummy value "I am DKIM, but change with the DKIM from finalize.sh" is created \(`dns.tr` file\) for ones convenience - that value needs to be replaced with the above highlighted DKIM value provided by the finalize.sh script. 

Ideally, this step would be automated during the droplet bootstrapping, but I was not yet able to do that due to some Terraform bugs I encountered. 

Below shows \(top to bottom\):

* terraform config that sets up a new DNS TXT record placeholder for DKIM
* terraform creating the DNS TXT record based on the above config from `dns.tf`
* the actual result - DNS TXT record placeholder for `redteam.me` domain

![](../../.gitbook/assets/screenshot-from-2019-01-29-21-17-16.png)

## Download & Try

If you would like to test this setup, feel free to grab the config files here:

{% embed url="https://github.com/mantvydasb/Red-Team-Infrastructure-Automation" %}

## References

{% embed url="https://bluescreenofjeff.com/2016-03-22-strengthen-your-phishing-with-apache-mod\_rewrite-and-mobile-user-redirection/" %}

{% embed url="https://rastamouse.me/2017/08/automated-red-team-infrastructure-deployment-with-terraform-part-1/" %}

{% embed url="https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy" %}

{% embed url="https://developers.digitalocean.com/documentation/changelog/api-v2/new-size-slugs-for-droplet-plan-changes/" %}



