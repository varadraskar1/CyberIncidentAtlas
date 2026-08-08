# CyberIncidentAtlas Data Methodology

## 1. Purpose

CyberIncidentAtlas is an open, evidence-backed knowledge base of significant cybersecurity incidents.

The project aims to preserve structured information about cybersecurity incidents in a form that is:

- Human-readable
- Machine-readable
- Reproducible
- Auditable
- Research-friendly
- Continuously maintainable

The dataset prioritizes accuracy and traceability over the number of incidents collected.

---

# 2. What Counts as an Incident?

An incident may be included when there is credible evidence of a significant cybersecurity event involving one or more of the following:

- Unauthorized access
- Data breach
- Data exposure
- Ransomware
- Malware
- Cyber espionage
- Destructive cyber attack
- Denial-of-service attack
- Supply-chain compromise
- Cloud compromise
- Credential compromise
- Vulnerability exploitation
- Insider threat
- Critical infrastructure attack
- Large-scale fraud enabled by cyber compromise

An incident does not need to result in public disclosure of stolen data to qualify.

---

# 3. Incident Inclusion Criteria

CyberIncidentAtlas prioritizes incidents that have one or more significant characteristics:

- Large number of affected individuals or organizations
- Significant financial impact
- Major operational disruption
- Critical infrastructure involvement
- Government involvement
- Important cybersecurity implications
- Significant vulnerability exploitation
- Major threat actor involvement
- Novel or technically significant attack techniques
- Supply-chain implications
- Historical importance
- Strong educational or research value

The project does not attempt to record every minor cybersecurity event.

---

# 4. Evidence Hierarchy

Sources are classified according to their reliability.

## Tier 1 — Primary / Official Evidence

Highest priority.

Examples:

- Company incident disclosures
- Regulatory filings
- Government reports
- Court documents
- Law-enforcement statements
- Official investigation reports
- Official vulnerability databases

Examples include:

- CISA
- NIST
- SEC
- FTC
- FBI
- Government investigations
- Official company disclosures

---

## Tier 2 — High-Quality Secondary Evidence

Examples:

- Established cybersecurity research organizations
- Major security vendors
- Academic publications
- Reputable investigative journalism
- Industry research reports

These sources may provide technical details not available in primary disclosures.

---

## Tier 3 — Supporting Sources

Examples:

- Security publications
- Industry news
- Technical blogs
- Specialized cybersecurity journalism

These may support contextual information but should not be the sole basis for critical claims when stronger evidence exists.

---

## Tier 4 — Discovery Sources

Examples:

- Social media
- Forums
- Anonymous posts
- Unsourced websites
- Unverified claims

Tier 4 sources may be used to discover leads.

They should generally not be used as the sole evidence for important incident facts.

---

# 5. Evidence and Claims

CyberIncidentAtlas distinguishes between:

### Confirmed Facts

Information directly supported by reliable evidence.

Example:

> A vulnerability was exploited.

### Reported Claims

Information reported by a credible source but not independently confirmed.

Example:

> Researchers attributed the incident to Threat Actor X.

### Analysis

Interpretation derived from available evidence.

Example:

> Network segmentation could have reduced the attacker's ability to access additional systems.

Facts, claims, and analysis must not be presented as equivalent.

---

# 6. Confidence Levels

Each incident receives an overall confidence rating.

## High

Multiple reliable sources support the core facts.

## Medium

Reliable evidence exists, but some important details remain uncertain.

## Low

The incident is credible but significant details remain unverified or disputed.

## Unknown

There is insufficient evidence to assign a meaningful confidence level.

Confidence should never be used to imply certainty where the evidence does not support it.

---

# 7. Attribution

Threat-actor attribution must be treated separately from incident confirmation.

The existence of an incident does not prove the identity of the attacker.

Attribution may be classified as:

- Confirmed
- High confidence
- Medium confidence
- Low confidence
- Suspected
- Unknown
- Disputed

Attribution claims should identify who made the attribution when possible.

For example:

- Government attribution
- Security researcher attribution
- Company attribution
- Threat actor self-claim

A threat actor claiming responsibility is not automatically treated as proof of attribution.

---

# 8. Dates

Cybersecurity incidents often have multiple relevant dates.

Where available, the dataset distinguishes between:

- Initial intrusion
- Initial compromise
- First observed malicious activity
- Discovery
- Containment
- Public disclosure
- Regulatory disclosure
- Investigation
- Remediation

If the exact date is unknown, the dataset should not invent one.

Approximate dates may be represented as approximate when supported by evidence.

---

# 9. Affected Records

The number of affected records must be treated carefully.

Different sources may report different figures.

CyberIncidentAtlas should preserve meaningful disagreements rather than silently selecting a convenient number.

Possible classifications include:

- Confirmed
- Estimated
- Reported
- Potential
- Unknown

If multiple credible figures exist, the underlying sources should be preserved.

---

# 10. Vulnerabilities

Vulnerabilities should be identified using standardized identifiers where possible.

Examples:

- CVE identifiers
- CWE identifiers
- Vendor advisory identifiers

A vulnerability should only be linked to an incident when there is credible evidence connecting the vulnerability to that incident.

The existence of a CVE alone does not prove that it was exploited in a particular incident.

---

# 11. MITRE ATT&CK Mapping

MITRE ATT&CK techniques may be associated with incidents when the available evidence supports the mapping.

Mappings should not be added simply because a technique is theoretically possible.

For example:

If evidence shows that attackers exploited an internet-facing application, a mapping to:

`T1190 — Exploit Public-Facing Application`

may be appropriate.

If there is no evidence that attackers used phishing, the incident should not automatically receive a phishing technique.

---

# 12. Root Cause

Root cause should be based on evidence rather than hindsight.

Possible root causes include:

- Unpatched vulnerability
- Weak authentication
- Credential compromise
- Misconfiguration
- Excessive privileges
- Insecure software
- Insufficient segmentation
- Supply-chain compromise
- Insider activity
- Social engineering
- Unknown

Multiple root causes may exist.

---

# 13. Sources

Every incident must contain at least one source.

Important claims should be traceable to their supporting sources whenever possible.

Preferred sources are:

1. Primary sources
2. Government sources
3. Security research
4. Academic research
5. Reputable journalism
6. Industry publications

Sources should be preserved even if information later changes.

Broken or unavailable sources should be marked rather than silently removed when they are historically important.

---

# 14. Corrections

CyberIncidentAtlas is expected to evolve.

If new evidence contradicts an existing record:

- Do not silently overwrite important historical information.
- Update the record using stronger evidence.
- Document significant corrections.
- Preserve the reasoning behind major changes.

Accuracy takes priority over consistency with older entries.

---

# 15. No Stolen Data

CyberIncidentAtlas documents cybersecurity incidents.

It does not redistribute stolen information.

The repository must not contain:

- Passwords
- Authentication tokens
- API keys
- Private credentials
- Personal addresses of victims
- Financial account details
- Government identification numbers
- Database dumps
- Stolen documents containing sensitive personal information
- Malware samples containing live credentials

The project may describe categories and quantities of compromised information without reproducing the information itself.

---

# 16. Responsible Handling of Security Information

The project focuses on historical, analytical, and defensive cybersecurity information.

Incident records should describe attack techniques at a level useful for research and defense without unnecessarily publishing active secrets or sensitive access information.

---

# 17. Research Integrity

CyberIncidentAtlas should prioritize:

- Accuracy over speed
- Evidence over speculation
- Transparency over completeness
- Reproducibility over convenience
- Primary evidence over repetition
- Explicit uncertainty over false precision

When the evidence does not support a conclusion, the correct value is:

`unknown`

not a guess.

---

# 18. Data Quality

Before an incident is accepted, contributors should verify:

- Incident identity
- Victim organization
- Relevant dates
- Incident classification
- Impact
- Sources
- Vulnerability relationships
- Threat-actor attribution
- MITRE ATT&CK mappings
- Confidence level

Automated validation should be used wherever possible.

---

# 19. Versioning

CyberIncidentAtlas follows version-controlled data practices.

Changes to:

- Incident records
- Schemas
- Methodology
- Mappings
- Scripts

should be committed to Git with meaningful commit messages.

Major schema changes should receive explicit version identifiers.

---

# 20. Guiding Principle

> If we cannot explain where a fact came from, we should not present it as a fact.