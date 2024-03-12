# 0 Day Mitigations
Practical steps to help mitigate the risk of Zero-Day vulnerabilities. A presentation delivered to the [College IT Conference 2024](https://citc.college/).

**As a presentation on YouTube:** Coming soon!

By **James Preston** of [ANSecurity](https://www.ansecurity.com/).

<details>
<summary>Introduction</summary>

  ## By the end of this presentation you will

* Understand the common elements in some recent Zero-Day vulnerabilities
* Be familiar with hide
* Be able to take some immediate steps to help reduce the risk of impact from Zero-Day vulnerabilities
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

* 'Our immediate advice is to upgrade your PaperCut Application Servers to one of the fixed versions listed below if you haven’t already.'
* Reported to Papercut by Trend Micro as already under exploitation.
* Commonly Internet accessible within the University.
* Unauthenticated attacker could perform remote code execution on a PaperCut application server.

## Ivanti Connect (and Policy) Secure
https://www.ivanti.com/blog/security-update-for-ivanti-connect-secure-and-ivanti-policy-secure-gateways

https://forums.ivanti.com/s/article/CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways

https://forums.ivanti.com/s/article/CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure

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
  
## No single one of these pratices will save you, think in layers!

* **Hide**
  * Not the best option but it will buy you time
  * Does your service appear on Shodan.io listed as that service?
* **Block access from and to known malicious**
  * It's already known to be malicious - why wouldn't you block it?
* **Restrict opportunities for execution**
  * Block file transfer, sandbox, block unrecognised file execution
* **Detect and prevent abnormal activities**
  * Block access from and to known malicious
  * Why is that server reaching out to threatactor420.com?
* **Limit the overall impact/scope**
  * Ok you’ve been compromised, lets prevent lateral movement

## Not all threat actors are the same

* Casual
  * Doesn't take much to stop
* Determined - low skill
  * Hiding probably won't work
* Determined - high skill
  * Realistic probibility will have access to an exploit before you've patched
* Nation State/Advanced persistent threat
  * Highly likely will have access to an exploit before you've patched

</details>

<details>
<summary>Buying time - 1</summary>

## Hide

* Limit the scope of inbound connections.
  * By country (either deny known bad or permit only countries with a legtimate reason to access)
  * By IP address block.
    * Just JANET - https://bgpview.io/asn/786#prefixes-v4
    * Just Oxford/Cambridge - https://help.it.ox.ac.uk/ip-addresses or https://help.uis.cam.ac.uk/service/network-services/ip/cam-ip-ranges
    * Specific IPs or specific ranges
    * Port knocking??
      * Palo Alto Networks NGFW - https://live.paloaltonetworks.com/t5/community-blogs/knock-knock-who-s-there/ba-p/417975
* Where possible publish a VPN or VPN web portal to present services.

## Hide - at a minimum

* Block inbound connections from 'unfriendly' countries
  * https://www.gov.uk/government/publications/the-uk-sanctions-list
  * https://ofac.treasury.gov/sanctions-programs-and-country-information

 Do you really need to allow inbound connections to your student meals booking system from Afghanistan?

</details>

<details>
<summary>Buying time - 2</summary>

## Block access from and to known malicious

</details>

<details>
<summary>Buying time - 3</summary>

## Restrict opportunities for execution

</details>

<details>
<summary>Buying time - 4</summary>

## Detect and prevent abnormal activities

</details>

<details>
<summary>Buying time - 5</summary>

## Limit the overall impact/scope

* DMZs! Why did they ever go away?
* Client firewall configuration.
* User based policy.
* Internal IDS/IPS – same level of strictness as inbound.
  * Normally internal is more lax.

</details>

<details>
  
<summary>Lets secure something</summary>

## Ruckus Wireless Controller (SmartZone)
![image](https://github.com/jamesfed/0DayMitigations/assets/28963928/7faf91c1-246a-4bec-806d-b39278d3adc6)

* Can't install AV/EDR/UEBA agents.
* No access to underlying Operating System detailed logging.
* 

</details>

<details>
<summary>Title</summary>

</details>

<details>
<summary>Title</summary>

</details>

<details>
<summary>Title</summary>

</details>

<details>
<summary>Title</summary>

</details>

<details>
<summary>Title</summary>

</details>
