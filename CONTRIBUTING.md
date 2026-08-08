# Contributing to CyberIncidentAtlas

Thank you for contributing to CyberIncidentAtlas.

CyberIncidentAtlas is an evidence-backed, open cybersecurity incident knowledge base. Contributions are welcome, but data quality is more important than the number of incidents in the repository.

---

## 1. Before You Contribute

Please read:

- `README.md`
- `METHODOLOGY.md`
- `schemas/incident.schema.json`

The methodology defines how evidence, confidence, attribution, dates, sources, and uncertainty are handled.

---

# 2. What Can Be Contributed?

Contributors can submit:

- New cybersecurity incidents
- Corrections to existing incidents
- Additional sources
- Improved timelines
- Vulnerability mappings
- MITRE ATT&CK mappings
- Threat actor attribution supported by evidence
- Impact information
- Technical analysis
- Data-quality improvements
- Validation tooling
- Documentation improvements

---

# 3. Incident Selection

CyberIncidentAtlas focuses on significant cybersecurity incidents.

Good candidates include incidents involving:

- Major data breaches
- Ransomware
- Large-scale malware campaigns
- Cyber espionage
- Critical infrastructure
- Supply-chain attacks
- Major vulnerability exploitation
- Large financial impact
- Significant operational disruption
- Historically important attacks
- Novel attack techniques
- Major threat actors

The project does not aim to record every minor security event.

When deciding whether an incident belongs in the dataset, consider its research, historical, technical, or defensive value.

---

# 4. Evidence Requirements

Every incident must contain at least one source.

Important claims should reference the source supporting them.

Preferred evidence hierarchy:

1. Primary / official sources
2. Government investigations
3. Security research
4. Academic research
5. Reputable journalism
6. Industry publications
7. Other supporting sources

Social media, forums, and anonymous posts may help discover information, but they should generally not be the sole evidence for important claims.

---

# 5. Do Not Turn Reports Into Facts

Cybersecurity reporting often contains uncertainty.

For example:

> "Security researchers believe the attack was conducted by Group X."

Do not rewrite this as:

> "Group X conducted the attack."

Instead preserve the uncertainty and attribution source.

CyberIncidentAtlas distinguishes between:

- Confirmed
- Reported
- Suspected
- Disputed
- Analysis

Do not remove uncertainty simply to make a record look cleaner.

---

# 6. Source References

Sources are maintained in the central registry:

```text
data/sources/sources.yaml
```

Every source has a globally unique six-digit source ID.

Example:

```yaml
source_id: SRC-000001
url: "https://example.com/report"
source_type: security_research
```

Incident records reference these global source IDs using `source_refs`.

Example:

```yaml
source_refs:
  - SRC-000001
  - SRC-000004
```

Do **not** create local source IDs such as:

```text
SRC-001
SRC-002
SRC-003
```

When adding a new source:

1. Check `data/sources/sources.yaml`.
2. Find the next available `SRC-XXXXXX` ID.
3. Add the source to the central registry.
4. Reference that ID from the incident using `source_refs`.
5. Run the validator.

Every `source_refs` value must correspond to an existing source in the central registry.

Run:

```powershell
py scripts/validate.py
```

before submitting a contribution.
