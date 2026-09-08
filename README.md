# Entra ID Security Lab

A defensive identity-security engineering lab focused on reviewing Microsoft Entra ID posture, identifying risky identity conditions, prioritizing remediation, and validating access-control improvements using synthetic data.

## Objectives

- Detect high-risk identity and access conditions.
- Identify administrative privilege concentration.
- Flag weak MFA and conditional-access coverage.
- Review risky service principals and application permissions.
- Highlight dormant privileged identities.
- Produce remediation-ready findings with transparent scoring.

## Repository Structure

```text
src/entra_posture.py          posture analysis engine
data/identities.json          synthetic identity dataset
tests/test_entra_posture.py   unit tests
docs/remediation-guide.md     remediation and validation guidance
```

## Risk Model

The analyzer combines multiple identity signals rather than relying on a single severity label.

| Signal | Example risk |
|---|---|
| Privileged role | Global Administrator, Privileged Role Administrator |
| MFA coverage | Privileged identity without MFA |
| Conditional Access | Identity excluded from baseline policy |
| Dormancy | Privileged account inactive beyond threshold |
| Application permission | Broad application privilege such as tenant-wide directory write |
| Credential age | Long-lived application secret or credential |

The output is intended to support triage and remediation prioritization; it is not evidence of compromise.

## ATT&CK Context

Relevant defensive mappings include:

- T1078 - Valid Accounts
- T1098 - Account Manipulation
- T1136 - Create Account
- T1556 - Modify Authentication Process
- T1528 - Steal Application Access Token

ATT&CK mappings describe security relevance and expected telemetry, not proof that a technique occurred.

## Usage

```bash
python src/entra_posture.py data/identities.json
python -m unittest discover -s tests
```

## Engineering Workflow

```text
Identity Inventory
      ↓
Privilege & Authentication Review
      ↓
Policy / Application Permission Analysis
      ↓
Risk Scoring
      ↓
Remediation Ownership
      ↓
Control Validation
      ↓
Residual Risk Reporting
```

## Safety

All identities, tenants, domains, object IDs and credentials used in this repository are synthetic. The project contains no production tenant data, secrets, employer/client information, credential-theft functionality or unauthorized access workflows.
