# CVE-2026-35273: Unauthenticated RCE in Oracle PeopleSoft PSEMHUB

**Severity:** Critical (CVSS 9.8)
**Affected Products:** Oracle PeopleSoft Enterprise PeopleTools (8.61, 8.62)
**Protocol Surface:** HTTP/HTTPS (TCP 80/443)
**First Observed Exploitation:** May 27, 2026 – June 9, 2026
**Advisory:** [Oracle Security Alert - June 2026 (CPU187)](https://www.oracle.com/security-alerts/)
**CWE:** CWE-306 (Missing Authentication for Critical Function)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Background: PSEMHUB and PeopleSoft Architecture](#2-background-psemhub-and-peoplesoft-architecture)
3. [Vulnerability Analysis](#3-vulnerability-analysis)
4. [Attack Kill Chain](#4-attack-kill-chain)
5. [Post-Exploitation Behavior](#5-post-exploitation-behavior)
6. [Detection Engineering](#6-detection-engineering)
7. [Threat Intelligence & Attribution Context](#7-threat-intelligence--attribution-context)
8. [Mitigation & Hardening](#8-mitigation--hardening)
9. [Indicators of Compromise](#9-indicators-of-compromise)
10. [Sigma Rules](#10-sigma-rules)
11. [KQL Queries](#11-kql-queries)
12. [Suricata Signatures](#12-suricata-signatures)
13. [References](#13-references)
14. [Conclusion](#14-conclusion)

---

## 1. Executive Summary

Between May 27, 2026, and June 9, 2026, ThreatSignal identified active, zero-day exploitation of **CVE-2026-35273**, a critical remote code execution (RCE) vulnerability affecting Oracle PeopleSoft Enterprise PeopleTools. The vulnerability carries a CVSS score of 9.8 and allows unauthenticated attackers to execute arbitrary code on the affected server.

The flaw originates from missing authentication controls (CWE-306) in the Environment Management Hub (PSEMHUB) component. By sending crafted `POST` requests to the `/PSEMHUB/hub/` endpoint and chaining requests to `/PSIGW/HttpListeningConnector`, an unauthenticated attacker can achieve Server-Side Request Forgery (SSRF) that escalates directly to RCE.

This writeup details the zero-day exploitation campaign orchestrated by the threat actor **UNC6240 (ShinyHunters)**, who weaponized this vulnerability primarily against the higher education sector. 

---

## 2. Background: PSEMHUB and PeopleSoft Architecture

### 2.1 PeopleSoft Deployment Topology

A standard enterprise PeopleSoft deployment consists of several tiers:

| Component | Role |
|---|---|
| **PeopleSoft Web Server (PIA)** | Java EE web application deployed on Oracle WebLogic, handles user-facing HTTP requests |
| **PeopleSoft Application Server (PSAPPSRV)** | Tuxedo-based middleware that handles business logic |
| **PeopleSoft Integration Broker (PSIGW)** | Gateway component enabling communication with external systems via web services |
| **Environment Management Hub (PSEMHUB)** | Java web application managing patch and update deployment across the environment |

Critically, the **PIA/WebLogic tier is commonly the only externally internet-accessible layer**, with the application server and integration broker expected to be reachable only from internal management systems. However, PSEMHUB is co-deployed within the WebLogic server, and its failure to authenticate incoming requests means any user with HTTP access to the web server can reach it.

### 2.2 Role of the Environment Management Hub

The **PeopleSoft Environment Management Framework** is designed to manage the deployment of updates and patches across PeopleSoft environments. The core of this framework is the **Environment Management Hub (PSEMHUB)**, a Java web application deployed within the PeopleSoft web server (typically Oracle WebLogic).

PSEMHUB facilitates communication between Environment Management Agents installed on various PeopleSoft servers and the central Hub. Due to its role in distributing patches and configuration changes, PSEMHUB inherently possesses high privileges and broad access to the application environment. This architectural design - a high-privileged management component co-located with a public-facing web tier - dramatically amplifies the impact of the authentication bypass.

---

## 3. Vulnerability Analysis

### 3.1 Root Cause: Missing Authentication and SSRF-to-RCE Gadget Chain

The vulnerability is rooted in a complete failure to authenticate incoming HTTP requests to the `/PSEMHUB/hub/` servlet. This unauthenticated entry point becomes a launchpad for a multi-step exploitation chain:

1.  **Unauthenticated Entry Point:** The `/PSEMHUB/hub/` servlet is designed to accept XML-formatted messages from registered Environment Management Agents. The servlet did not enforce any authentication for these inbound messages, treating all callers as implicitly trusted.
2.  **SSRF via HttpListeningConnector:** By crafting specific XML payloads sent to `/PSEMHUB/hub/`, attackers discovered they could coerce the server into constructing and issuing a secondary server-side HTTP request to the internal PeopleSoft Integration Broker endpoint `/PSIGW/HttpListeningConnector`. Because this request originates from the server itself (localhost), it bypasses network-level access controls that would ordinarily block external access to the Integration Broker.
3.  **Privileged Authentication Bypass via Gadget Chain:** The Integration Broker, receiving what it interprets as a legitimate internal request, processes the payload through its own routing logic. Researchers identified specific Integration Broker "gadgets" - pre-existing service configurations - that could be triggered to authenticate as a privileged application user without supplying credentials. This is the critical escalation step from SSRF to privileged execution.
4.  **Arbitrary File Write and Code Execution:** Once operating with privileged context within the Integration Broker, the attacker can trigger operations that result in arbitrary file writes to the WebLogic deployment directory. In observed exploitation, this was used to write `.jsp` webshells into the `PSEMHUB.war` deployment path. Once written, the webshell is accessible via a standard HTTP `GET` request, achieving code execution in the security context of the WebLogic server process.

> **Analyst Note:** This is not a simple direct-write file upload. The exploitation requires a carefully sequenced multi-step chain: unauthenticated SSRF → internal broker request → gadget-based authentication escalation → arbitrary write. This complexity suggests prior research investment by the threat actor before the advisory was published.

---

## 4. Attack Kill Chain

The exploitation campaign observed in the wild followed a highly structured kill chain:

### 4.1 Initial Access (T1190)
Attackers initiated mass scanning for exposed PeopleSoft web interfaces. Upon identifying a vulnerable instance, they sent an unauthenticated, crafted XML `POST` request to `/PSEMHUB/hub/`.

### 4.2 Payload Delivery and Execution
The SSRF vulnerability was leveraged to write a Java Server Page (JSP) webshell directly into the `PSEMHUB.war` directory. These webshells were often given random alphanumeric names (e.g., `a7X9p.jsp`) to evade static signature detection.

### 4.3 Command and Control (C2) Establishment (T1071.001)
To establish persistent, interactive access, the attackers used the JSP webshell to download and execute custom agents. In this campaign, UNC6240 heavily relied on **MeshCentral**, an open-source remote management tool.
- The binaries were renamed to disguise their purpose, commonly observed as `meshagent*-azure-ops.exe` or similar Linux ELF variants.
- The agents communicated outbound to attacker-controlled infrastructure over standard HTTPS (e.g., `wss://azurenetfiles[.]net:443/agent.ashx`).

---

## 5. Post-Exploitation Behavior

Following successful C2 establishment, UNC6240 demonstrated rapid lateral movement and extortion tactics.

### 5.1 Internal Reconnaissance (TA0007)
Following initial access, UNC6240 conducted rapid internal enumeration using a combination of native Linux/Unix utilities and the established MeshCentral tunnel. The immediate focus was on identifying database servers, file servers, and domain infrastructure reachable from the compromised PeopleSoft host.

### 5.2 Lateral Movement via Credential Spraying (TA0008)
Attackers utilized custom bash scripts for rapid automated lateral movement. The primary tool was the `sshpass` utility, which was invoked within a "fanout" script named with a victim-specific abbreviation prefix (e.g., `UNIV_fanout.sh`). These scripts automated SSH credential spraying at scale:

- **Target Accounts:** Attackers prioritized common PeopleSoft and Unix service accounts, specifically including: `psoft`, `oracle`, and `linuxadm`.
- **Mechanism:** `sshpass -p <password> ssh` calls against discovered internal IP ranges with a hardcoded wordlist.
- **Scale:** The automated nature allowed rapid enumeration of hundreds of internal hosts within minutes of initial access.

### 5.3 Persistence (TA0003)
MeshCentral agents were configured to restart automatically and were commonly installed with names resembling legitimate Azure management tools (e.g., `meshagent32-azure-ops.exe`) to blend with expected network activity.

### 5.4 Exfiltration and Extortion (TA0010)
Data exfiltration was conducted over the established MeshCentral tunnels, utilizing the encrypted WSS channel to blend with normal HTTPS traffic. Following exfiltration, the attackers dropped an extortion note named `README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT` across compromised servers and user-accessible directories. The exfiltrated data was subsequently published on the ShinyHunters Data Leak Site (DLS), with notifications sent to victim organizations.

---

## 6. Detection Engineering

Detecting this attack requires a multi-layered approach, focusing on the initial exploit vector, the resulting file modifications, and the subsequent C2 traffic.

### 6.1 Network-Level Detection
- **Initial Exploit:** Monitor for `POST` requests to `/PSEMHUB/hub/` that contain XML payloads attempting to reference or route to `/PSIGW/HttpListeningConnector`.
- **C2 Traffic:** Alert on unexpected outbound TLS connections from the PeopleSoft application servers, particularly utilizing WebSockets (`wss://`) to unknown domains.

### 6.2 Host-Level Detection (WebLogic Server)
- **File Integrity Monitoring (FIM):** Alert on the creation of any new `.jsp` files within the `PSEMHUB.war` or `PSIGW.war` directories. This is the highest fidelity indicator of the initial compromise.
- **Process Monitoring:** Detect the execution of unusual child processes spawned by the Java process hosting WebLogic (e.g., `java.exe` or `java` spawning `cmd.exe`, `sh`, or unknown binaries like `meshagent`).

---

## 7. Threat Intelligence & Attribution Context

The exploitation of CVE-2026-35273 between May and June 2026 has been definitively attributed to **UNC6240**, a threat actor operating under the **ShinyHunters** extortion brand.

### 7.1 Targeting Profile
UNC6240's campaign was notable for its remarkable breadth and sector specificity:
- **Scale:** More than **100 organizations** were targeted during the 14-day zero-day window.
- **Sector Focus:** A striking **68% of targeted entities were in the higher education sector** - universities and colleges that rely on PeopleSoft Campus Solutions for student information systems, HR, and financial operations. This targeting is deliberate: higher-education institutions tend to have large, decentralized IT environments, slower patch cycles, and store extremely high-value personal data (student records, financial aid data, research data) that commands high extortion leverage.
- **Industry Diversity:** The remaining 32% spanned financial services, healthcare, and government entities, all known to run PeopleSoft ERP at scale.

### 7.2 Actor Profile
ShinyHunters (UNC6240) is a financially motivated extortion actor with a history of large-scale data theft operations. They are known for targeting SaaS platforms, cloud databases, and enterprise ERP systems - prioritizing environments where bulk sensitive data can be exfiltrated quickly and monetized through ransom or DLS publication. The integration of a legitimate remote management tool (MeshCentral, masquerading as an Azure service binary) demonstrates awareness of endpoint detection capabilities and is consistent with more sophisticated financially motivated actors moving away from custom malware.

### 7.3 Operational Assessment
The speed at which UNC6240 weaponized CVE-2026-35273 into an automated campaign - complete with custom `fanout.sh` scripts, victim-specific naming conventions, and a DLS publication workflow - indicates prior operational planning. It is assessed with moderate-to-high confidence that the threat actor had access to the vulnerability details or developed their exploit capability in the weeks prior to Oracle's June 10 advisory, consistent with a financially motivated group tracking enterprise software vulnerability research.

---

## 8. Mitigation & Hardening

### 8.1 Apply Vendor Patches (Primary Mitigation)

Immediately apply the June 2026 out-of-band Oracle Security Alert patches for PeopleTools 8.61 and 8.62 using **Patch Availability Document ID: CPU187** available via the [Oracle Support portal](https://support.oracle.com).

| Affected Version | Action |
|---|---|
| PeopleTools 8.61 | Apply June 2026 Oracle Security Alert patch |
| PeopleTools 8.62 | Apply June 2026 Oracle Security Alert patch |
| Earlier unsupported versions | Upgrade to a supported release and apply patch |

### 8.2 Restrict Access to PSEMHUB (Immediate Compensating Control)
If hotfix application is not immediately feasible, restrict the attack surface at the network and application layer:

- **Block External Access at WAF/Reverse Proxy:** The `/PSEMHUB/` URI path should **never** be reachable from external networks. Add explicit deny rules for `/PSEMHUB/*` and `/PSIGW/HttpListeningConnector*` on all edge devices.
- **Disable the Service:** If the Environment Management Framework is not actively used for patching, disable the PSEMHUB application entirely within the WebLogic administration console. This eliminates the attack surface completely.
- **Internal Network Segmentation:** Ensure PeopleSoft web tier hosts cannot initiate outbound connections to arbitrary external IPs. Strict egress filtering would have blocked the MeshCentral C2 callback in observed incidents.

### 8.3 Incident Response Actions

Due to the zero-day exploitation window (May 27 – June 9, 2026), organizations running vulnerable versions must treat this as a potential breach scenario, not merely a patching event.

| Action | Detail |
|---|---|
| **Log Review** | Audit WebLogic access logs for `POST` requests to `/PSEMHUB/hub/` or `/PSIGW/HttpListeningConnector` from external IP addresses, dating back to May 27, 2026 |
| **File Audit** | Scan all WebLogic deployment directories for `.jsp` files not present in the original application archive |
| **Process Review** | Examine running processes and process history on PeopleSoft servers for unexpected binaries, especially those referencing `azure-ops` in their name |
| **Network Review** | Inspect firewall and proxy logs for outbound WebSocket connections (`wss://`) to untrusted domains from PeopleSoft servers |
| **Account Audit** | Review SSH authentication logs for the accounts `psoft`, `oracle`, and `linuxadm` for evidence of credential spraying activity |

---

## 9. Indicators of Compromise

Verified IOCs from the UNC6240 campaign have been separated into network-based and host-based CSV files:

- **[network-iocs.csv](ioc/network-iocs.csv):** Contains MeshCentral C2 domains and attacker IP addresses.
- **[host-iocs.csv](ioc/host-iocs.csv):** Contains filenames for the disguised agents, extortion notes, and lateral movement scripts.
- **[hashes.txt](samples/hashes.txt):** Intelligence gap notice - no confirmed static hashes for the MeshCentral agents have been published by authoritative sources at this time. The file includes hunting guidance to use behavioral detection in lieu of hash-based matching.

---

## 10. Sigma Rules

We have developed Sigma rules to detect the post-exploitation behavior:

- **[rule-psemhub-webshell.yml](detection/sigma/rule-psemhub-webshell.yml):** Detects the creation of JSP webshells in the WebLogic deployment directory.
- **[rule-meshcentral-agent-execution.yml](detection/sigma/rule-meshcentral-agent-execution.yml):** Detects execution of the disguised MeshCentral agent binaries.
- **[rule-sshpass-lateral-movement.yml](detection/sigma/rule-sshpass-lateral-movement.yml):** Detects the use of `sshpass` for credential spraying, a key tactic of the `fanout.sh` scripts.

---

## 11. KQL Queries

Kusto Query Language (KQL) queries for Microsoft Sentinel/Defender environments:

- **[query-psemhub-rce.kql](detection/kql/query-psemhub-rce.kql):** Hunts for the unauthenticated POST requests targeting the vulnerable endpoint.
- **[query-webshell-process-creation.kql](detection/kql/query-webshell-process-creation.kql):** Hunts for suspicious child processes spawned by the WebLogic server.
- **[query-outbound-websocket.kql](detection/kql/query-outbound-websocket.kql):** Hunts for unusual outbound WebSocket traffic indicative of MeshCentral C2.

---

## 12. Suricata Signatures

Network-level intrusion detection signatures to inspect traffic:

- **[cve-2026-35273-exploit.rules](detection/suricata/cve-2026-35273-exploit.rules):** Detects the SSRF payload attempting to reach the HttpListeningConnector via PSEMHUB.
- **[meshcentral-c2.rules](detection/suricata/meshcentral-c2.rules):** Detects plaintext HTTP/WebSocket setup traffic for the specific MeshCentral C2 domains.

---

## 13. References

- **Oracle Security Alert (CPU187):** [https://www.oracle.com/security-alerts/](https://www.oracle.com/security-alerts/)
- **NVD Entry:** [CVE-2026-35273](https://nvd.nist.gov/vuln/detail/CVE-2026-35273)
- **Rapid7 Analysis:** [AttackerKB - CVE-2026-35273](https://attackerkb.com/topics/CVE-2026-35273)
- **UNC6240 Threat Research (Google TAG):** [https://cloud.google.com/blog/topics/threat-intelligence](https://cloud.google.com/blog/topics/threat-intelligence)

---

## 14. Conclusion

CVE-2026-35273 is a textbook case of why management and administrative interfaces must never be co-located with public-facing web tiers without strict authentication controls. The PSEMHUB endpoint was both fully unauthenticated and reachable from the internet - a combination that reduced the barrier to full system compromise to a single crafted HTTP request.

The UNC6240 campaign underscores several important lessons:

1. **Zero-day windows are exploitation windows.** The 14 days between first observed exploitation (May 27) and vendor patch availability (June 10) represent a structural advantage for well-resourced attackers who can develop and operationalize exploits ahead of disclosure.
2. **Management components are high-value targets.** PSEMHUB's privileged role in the environment meant that compromising it granted attackers capabilities far beyond a typical web application compromise.
3. **Egress filtering is an undervalued control.** Strict outbound network controls would have severed the MeshCentral C2 channel even after the initial webshell was deployed, significantly limiting post-exploitation impact.
4. **Legitimate tooling is the new malware.** UNC6240's use of MeshCentral - a legitimate, signed remote management tool - as their primary C2 mechanism demonstrates that detection strategies relying solely on malware signatures are increasingly insufficient.

Organizations relying on PeopleSoft should treat this incident as a forcing function to audit all internet-facing management endpoints, enforce strict egress filtering from application servers, and accelerate patch cadences for ERP platforms.

---

*This writeup is part of ThreatSignal's technical research series. For questions, engagement requests, or to share threat intelligence, contact our research team via the repository.*

*Last Updated: June 2026*
