# 0 Day Mitigations
Practical steps to help mitigate the risk of Zero-Day vulnerabilities.

By James Preston of [ANSecurity](https://www.ansecurity.com/).

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
https://logging.apache.org/log4j/2.x/security.html
* Existed unnoticed since 2013
* Privately disclosed
* Widely used, not always easy to determine if in use on 'appliances'
* Simple to exploit

## Papercut
https://www.papercut.com/kb/Main/PO-1216-and-PO-1219
* Reported to Papercut by Trend Micro as already under exploitation.
* Commonly Internet accessible within the University.

## Ivanti Connect Secure
https://forums.ivanti.com/s/article/CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure?language=en_US
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

![image](https://github.com/jamesfed/0DayMitigations/assets/28963928/89a0f89b-93bd-4242-9602-6c72ee3776b3)

* Information from Verizon Data Breach Investigation Report

</details>

<details>
<summary>Buying time</summary>

* Hide
  * Not the best option but it will buy you time
  * Does your service appear on Shodan.io listed as that service?
* Block access from and to known malicious
  * It's already known to be malicious - why wouldn't you block it?
* Restrict opportunities for execution
  * Block file transfer, sandbox, block unrecognised file execution
* Detect and prevent abnormal activities
  * Block access from and to known malicious
  * Why is that server reaching out to threatactor420.com?
* Limit the overall impact/scope
  * Ok you’ve been compromised, lets prevent lateral movement

</details>

<details>
<summary>Buying time - 1</summary>

## Hide

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
