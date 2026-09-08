# Entra ID Remediation and Validation Guide

## Purpose

Translate identity posture findings into practical control improvements and verify that remediation reduces measurable exposure.

## Priority Controls

### Privileged identity without MFA
- **Impact:** compromise can expose high-impact administrative control.
- **Risk:** high to critical depending on assigned role and access path.
- **Remediation:** require phishing-resistant MFA where feasible, remove unnecessary standing privilege, and use privileged identity management for eligible assignments.
- **Validation:** confirm authentication-method registration, policy enforcement, and absence of unintended policy exclusions.

### Conditional Access exclusion
- **Impact:** excluded identities may bypass baseline access restrictions.
- **Risk:** medium to high depending on privilege and exposure.
- **Remediation:** review exclusions, document justified break-glass exceptions, and minimize permanent bypasses.
- **Validation:** simulate/evaluate policy outcome and confirm expected controls apply.

### Dormant privileged identity
- **Impact:** unnecessary privileged identities increase attack surface.
- **Risk:** high when inactivity is prolonged and privilege remains active.
- **Remediation:** disable or remove role assignment after ownership validation; use time-bound eligible privilege for legitimate future need.
- **Validation:** confirm role removal and verify no dependent workflow was disrupted.

### High-impact application permission
- **Impact:** application compromise can grant broad directory access.
- **Risk:** high where permissions allow tenant-wide modification or role administration.
- **Remediation:** apply least privilege, replace broad permissions with narrower scopes where supported, review admin consent, rotate credentials, and prefer workload identities/federation over long-lived secrets.
- **Validation:** re-enumerate effective application permissions and test required business function under the reduced permission set.

### Long-lived application credential
- **Impact:** extended credential lifetime increases exposure window.
- **Risk:** medium, potentially high when combined with broad permissions.
- **Remediation:** rotate credentials, shorten lifetime, and prefer managed identities or workload identity federation where applicable.
- **Validation:** confirm old credential revocation and successful operation using the replacement identity mechanism.

## Governance Metrics

Useful metrics include:
- privileged identities without strong MFA;
- standing versus eligible privileged assignments;
- dormant privileged accounts;
- Conditional Access exclusions;
- service principals with high-impact application permissions;
- application credentials exceeding policy age;
- remediation aging and exception count.

## Evidence Standard

Retain sanitized evidence showing the condition before remediation, approved ownership/action, the configuration change, and a post-change validation result. ATT&CK mappings should be used for threat context rather than as proof of malicious activity.
