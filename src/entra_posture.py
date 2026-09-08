import json
import sys
from pathlib import Path

PRIVILEGED_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Application Administrator",
}


def score_identity(identity: dict) -> dict:
    score = 0
    reasons = []

    roles = set(identity.get("roles", []))
    privileged = bool(roles & PRIVILEGED_ROLES)

    if privileged:
        score += 30
        reasons.append("privileged role assigned")

    if privileged and not identity.get("mfa_enabled", False):
        score += 35
        reasons.append("privileged identity without MFA")

    if not identity.get("conditional_access_covered", True):
        score += 20
        reasons.append("not covered by baseline Conditional Access")

    inactive_days = identity.get("inactive_days", 0)
    if privileged and inactive_days >= 60:
        score += 20
        reasons.append("dormant privileged identity")

    if identity.get("type") == "service_principal":
        permissions = set(identity.get("application_permissions", []))
        broad = {"Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory"}
        if permissions & broad:
            score += 35
            reasons.append("high-impact application permission")
        if identity.get("credential_age_days", 0) >= 180:
            score += 15
            reasons.append("long-lived application credential")

    if score >= 70:
        severity = "critical"
    elif score >= 45:
        severity = "high"
    elif score >= 20:
        severity = "medium"
    else:
        severity = "low"

    return {
        "id": identity.get("id"),
        "display_name": identity.get("display_name"),
        "score": min(score, 100),
        "severity": severity,
        "reasons": reasons,
    }


def analyze(items: list[dict]) -> list[dict]:
    return sorted((score_identity(item) for item in items), key=lambda x: x["score"], reverse=True)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python src/entra_posture.py <identities.json>")

    path = Path(sys.argv[1])
    identities = json.loads(path.read_text(encoding="utf-8"))
    print(json.dumps(analyze(identities), indent=2))


if __name__ == "__main__":
    main()
