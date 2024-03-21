# 0 Day Mitigations
Practical steps to help mitigate the risk of Zero-Day vulnerabilities. A presentation delivered to the [College IT Conference 2024](https://citc.college/).

**As a presentation on YouTube:** Coming soon!

By **James Preston** of [ANSecurity](https://www.ansecurity.com/).

<details>
<summary>Introduction</summary>

  ## By the end of this presentation you will

* Understand the common elements in some recent Zero-Day vulnerabilities.
* Be familiar with 5 methods to help prevent attacks that start with a Zero-Day exploit.
* Be able to take some immediate steps to help reduce the risk of impact from Zero-Day vulnerabilities.
</details>

<details>
<summary>Zero-Day vulnerability</summary>

  ## What is a Zero-Day vulnerability
* A vulnerability (perhaps under exploitation) in a system that is unknown to its owners, developers, or anyone capable of at least mitigating it if not full remediation.
* Once made public the extra scrutiny of such a system normally leads to more vulnerability discoveries.
* Multiple known and Zero-Day vulnerabilities are often chained together to perform an attack.
* Rarely the biggest actual issue to worry about (looking at those who haven’t setup MFA for everything yet!) but they do make great headlines.

</details>

<details>
<summary>Some Zero-Days that made it in the news</summary>

## Log4Shell (Log4j)
https://logging.apache.org/log4j/2.x/security.html#CVE-2021-44228

* 'JNDI lookup can be exploited to execute arbitrary code loaded from an LDAP server'
* Existed unnoticed since 2013.
* Privately disclosed.
* Widely used, not always easy to determine if in use on 'appliances'.
* Simple to exploit, lead to trivial remote code execution.

## PaperCut
https://www.papercut.com/kb/Main/PO-1216-and-PO-1219

https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-131a

* 'Our immediate advice is to upgrade your PaperCut Application Servers to one of the fixed versions listed below if you haven’t already.'
* Reported to Papercut by Trend Micro as already under exploitation.
* Commonly Internet accessible.
* Unauthenticated attacker could perform remote code execution on a PaperCut application server.

## Ivanti Connect (and Policy) Secure
https://www.ivanti.com/blog/security-update-for-ivanti-connect-secure-and-ivanti-policy-secure-gateways

https://forums.ivanti.com/s/article/CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways

https://forums.ivanti.com/s/article/CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure

https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060b

* 'If CVE-2024-21887 is used in conjunction with CVE-2023-46805, exploitation does not require authentication and enables a threat actor to craft malicious requests and execute arbitrary commands on the system.'
* Under active exploitation at time of discovery.
  * Some researchers are now attributing to Chinese state actors.
  * Following discovery, the threat actors started using alternative exploits.
* Threat actors bypassed authentication and delivered web shells to the appliance.
* Evidence of credential capture.

</details>

<details>
<summary>Do I need to worry about this?</summary>

## Why yes...

* https://www.shodan.io
* https://www.shodan.io/search?query=ip%3A129.67.0.0%2F16%2C163.1.0.0%2F16
* https://account.shodan.io/billing - go grab a one-time 'member' tier

![image](https://github.com/jamesfed/0DayMitigations/assets/28963928/89a0f89b-93bd-4242-9602-6c72ee3776b3)

## But perhaps not as much as you might think

[2023 Data Breach Investigations Report](https://www.verizon.com/business/resources/reports/dbir/)

* Using breached credentials is by far the most common method of access into an organisation.
* But exploiting a vulnerability (zero-day or otherwise) still makes the top 3. 

![image](https://github.com/jamesfed/0DayMitigations/assets/28963928/09874c1b-342f-4355-b9f8-9ada2a75eb8c)


</details>

<details>
<summary>Buying time</summary>

## Even if the Zero-Day is 'new' what comes after often isn't

### Log4Shell (Log4j)
![image](https://github.com/jamesfed/0DayMitigations/assets/28963928/c3e400db-6025-4022-842a-98a164a2d635)

### PaperCut
![image](https://github.com/jamesfed/0DayMitigations/assets/28963928/c33e06f1-9766-41d0-9533-0537cee5f18b)

### Ivanti Connect (and Policy) Secure
![image](https://github.com/jamesfed/0DayMitigations/assets/28963928/2071cd35-e341-4d4f-80ff-f7afcf729d8e)


  
## No single one of these practices will save you, think in layers!

* **Hide**
  * Not the best option but it will buy you time.
  * Does your service appear on Shodan.io listed as that service?
* **Block access from and to known malicious**
  * It's already known to be malicious - why wouldn't you block it?
* **Restrict opportunities for execution**
  * Block file transfer, sandbox, block unrecognised file execution.
* **Strictly control network traffic**
  * Why is that server reaching out to threatactor420.com?
* **Limit the overall impact/scope**
  * Ok you’ve been compromised, lets prevent lateral movement.

## Not all threat actors are the same

* Casual.
  * Do not take much to stop.
* Determined - low skill.
  * Hiding probably won't work.
* Determined - high skill.
  * Realistic probability will have access to an exploit before you've patched.
* Nation State/Advanced persistent threat.
  * Highly likely will have access to an exploit before you've patched.

</details>

<details>
<summary>Buying time - 1</summary>

## Hide

* Limit the scope of inbound connections.
  * By country (either deny known bad or permit only countries with a legitimate reason to access).
  * By IP address block.
    * Just JANET - https://bgpview.io/asn/786#prefixes-v4.
    * Just Oxford/Cambridge - https://help.it.ox.ac.uk/ip-addresses or https://help.uis.cam.ac.uk/service/network-services/ip/cam-ip-ranges.
    * Specific IPs or specific ranges.
    * Port knocking.
      * Palo Alto Networks NGFW - https://live.paloaltonetworks.com/t5/community-blogs/knock-knock-who-s-there/ba-p/417975.
* Where possible publish a VPN or VPN web portal to present services.

## Hide - at a minimum

* Block inbound connections from 'unfriendly' countries.
  * https://www.gov.uk/government/publications/the-uk-sanctions-list.
  * https://ofac.treasury.gov/sanctions-programs-and-country-information.

 Do you really need to allow inbound connections to your student meals booking system from Afghanistan?

</details>

<details>
<summary>Buying time - 2</summary>

## Block access from and to known malicious

* Use the blocklists from your firewall vendor.
* https://iplists.firehol.org/?ipset=firehol_level1 - really powerful and highly trustworthy.
  * Watch out for the RFC1918 addresses that are included!
* Start and maintain information sharing partnerships.
* Outbound URL filtering with deny access to known malicious categories.
  * Command and Control, Hacking, Malware, Newly Registered Domains, Parked, Phishing, Unclassified/Unknown.
* **Alert** on attempts to access something malicious (even if just once a day).

![image](https://github.com/jamesfed/0DayMitigations/assets/28963928/3a099ad3-70a4-473e-a648-2aab597b819d)

</details>

<details>
<summary>Buying time - 3</summary>

## Restrict opportunities for execution

* Install anti-malware everywhere!
  * Yes on Linux as well 😉.
* Establish a baseline of what is permitted.
  * File hashes, file publishers, signed scripts, avoid filenames.
* Prevent the execution of everything else.
* **Alert** on attempts to execute something new (even if just once a day).

Resources:

* https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-overview
* https://docs.sophos.com/central/customer/help/en-us/ManageYourProducts/ServerProtection/ServerConfigureLockdown/index.html
* https://docs.sophos.com/central/customer/help/en-us/ManageYourProducts/ServerProtection/ServerConfigureLinuxRTD/index.html
* https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
* https://github.com/Sysinternals/SysmonForLinux

For when you can't:

* Look for integrity checkers.
  * https://forums.ivanti.com/s/article/KB44755.
  * https://support.microsoft.com/en-gb/topic/use-the-system-file-checker-tool-to-repair-missing-or-corrupted-system-files-79aa86cb-ca52-166a-92a3-966e85d4094e.
* Often run on-bootup on modern operating systems.
  * Consider which systems might not have a regular reboot.
* Run at times of high risk, before performing system upgrades, and consider running at regular intervals.

</details>

<details>
<summary>Buying time - 4</summary>

## Strictly control network traffic

* Based on
  * IP Address
  * Domain
  * URL
  * Application
  * Protocol/Port
* Where possible also
  * User
  * Device health

### All together now - decryption!

* Without performing decryption (where possible) you simply don't have visibility into what's coming into and leaving your services.
  * Decryption works with TLS 1.3.
  * Inbound decryption works with pratically everything you are likely to deploy.
  * Outbound decryption works on Linux and even some 'appliances'.
  * Grants anti-malware protections to machines that don't/can't have an agent installed on.

![image](https://github.com/jamesfed/0DayMitigations/assets/28963928/e82d237e-9830-4b5f-a813-e55206d6855b)

https://ubuntu.com/server/docs/security-trust-store

![image](https://github.com/jamesfed/0DayMitigations/assets/28963928/316aebb8-fdf9-48d7-8e85-b632e0d01b05)

So let's download some web shells!

![image](https://github.com/jamesfed/0DayMitigations/assets/28963928/c2b73d47-1b9a-4eb2-8f6b-4f2d8b31623c)

> "Deny by default" egress traffic restrictions are a best practice to follow for any servers, not just those running impacted versions of Log4j instances.

https://www.mandiant.com/resources/blog/log4shell-recommendations

</details>

<details>
<summary>Buying time - 5</summary>

## Limit the overall impact/scope

* DMZs! Why did they ever go away?
* Make use of client firewalls.
  * Deny access to management interfaces on the local subnet.
  * Permit management access from jump stations in a dedicated bastion network.
  * Bonus points - wrap network level access into that bastion network up in MFA!
* User based policy.
* Internal IDS/IPS – same level of strictness as inbound.
  * Normally internal is more lax.

![Cloud Service drawio (1)](https://github.com/jamesfed/0DayMitigations/assets/28963928/c49019eb-9b09-4b6a-ba8e-c5adfa071e04)

* https://www.youtube.com/watch?v=InPiE0EOArs - Amazing video on configuring the Windows firewall

</details>

<details>
  
<summary>Lets secure something - Example 1</summary>

## Ruckus Wireless Controller (SmartZone)
![image](https://github.com/jamesfed/0DayMitigations/assets/28963928/7faf91c1-246a-4bec-806d-b39278d3adc6)

* Can't install AV/EDR/UEBA agents.
* No access to underlying Operating System detailed logging.
* Although you can import CAs (for decryption) they are not supported for outbound connections.
* A threat actors dream with lots of CPU and RAM to play with.

</details>

<details>
<summary>Lets secure something</summary>



</details>

<details>
<summary>Lets secure something</summary>

## mmmmm network level anti-malware

Inbound decryption to the appliance from all networks (external and internal) allows the firewall full visibility into what's being uploaded.

So lets upload a webshell!

![image](https://github.com/jamesfed/0DayMitigations/assets/28963928/7b671390-0566-498e-8fdc-94ab5785c73e)

![image](https://github.com/jamesfed/0DayMitigations/assets/28963928/3467f6cc-3b96-4d54-85b7-14344811606e)

As the firewall sees the file go through it identifies it as spyware and is placed to block the connection while also alerting the administrator.

![image](https://github.com/jamesfed/0DayMitigations/assets/28963928/19a9d36c-29ab-47de-b053-f3b6c9a6a0dd)

</details>

<details>
<summary>Lets secure something - Example 2</summary>

## Linux web server

</details>

<details>
<summary>Lets secure something</summary>

## A series of firewall policies to

* Block known malicious IP addresses.
* Permit broad (not country restricted) inbound access to the main institution website.
* A series of geo-blocks.
* Permit all other inbound access to additional websites.
* Geo-allow rule for VPN service.
  * Consider having a form or similar which staff can submit travel plans to for allowing broader inbound access when needed.
* A rule to drop all other inbound traffic.

![image](https://github.com/jamesfed/0DayMitigations/assets/28963928/217968d6-c960-4b8a-a82d-d7d22a2d3495)

## If traffic is moving from DMZ to 'internal' zones over encrypted channels then decrypt!

* Don't let that small foothold spread.
* Detect brute force attacks.
* Detect further exploit attempts.
* All of these would be very noisy indicators that something is going wrong.

![image](https://github.com/jamesfed/0DayMitigations/assets/28963928/4a127609-7ec5-4df5-be55-eda1572d8305)

</details>

<details>
<summary>Lets secure something</summary>

</details>

<details>
<summary>Key take aways</summary>

## When you get back to your institutions

1. Consider how widley accessible your services need to be, consider geo-blocking and geo-allowing.
2. Leverage trustworthy block lists, see how many hits you are getting.
3. Install your anti-malware agents on **all** your servers - including Linux.
4. Restrict outbound and internal traffic from services that permit inbound connections from the Internet to the minimum required for their function.
5. Consider inbound/internal decryption to get the best value out of existing investments.

</details>
