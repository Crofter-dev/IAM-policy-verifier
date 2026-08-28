from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    statement: dict

def _as_list(value):
    if isinstance(value, str):
        return [value]
    return value or []

def flag_wildcard_action_and_resource(statement: dict) -> Finding | None:
    if statement.get("Effect") != "Allow":
        return None

    actions = _as_list(statement.get("Action"))
    resources = _as_list(statement.get("Resource"))

    if "*" in actions and "*" in resources:
        return Finding(
            rule_id="IAM001",
            severity=Severity.CRITICAL,
            message="Statement grants '*' action on '*' resource (full admin access)",
            statement=statement,
        )
    return None

def flag_wildcard_action_only(statement: dict) -> Finding | None:
    if statement.get("Effect") != "Allow":
        return None

    actions = _as_list(statement.get("Action"))
    if "*" in actions:
        return Finding(
            rule_id="IAM002",
            severity=Severity.HIGH,
            message="Statement grants wildcard '*' action",
            statement=statement,
        )
    return None

def flag_pass_role_without_condition(statement: dict) -> Finding | None:
    if statement.get("Effect") != "Allow":
        return None

    actions = _as_list(statement.get("Action"))
    if "iam:PassRole" in actions and "Condition" not in statement:
        return Finding(
            rule_id="IAM003",
            severity=Severity.HIGH,
            message="iam:PassRole granted without a restricting Condition",
            statement=statement,
        )
    return None

def flag_no_mfa_on_sensitive_action(statement: dict) -> Finding | None:
    sensitive_actions = {"iam:DeletePolicy", "iam:DeleteRole", "iam:DeleteUser"}
    if statement.get("Effect") != "Allow":
        return None

    actions = set(_as_list(statement.get("Action")))
    condition = statement.get("Condition", {})
    has_mfa = "Bool" in condition and "aws:MultiFactorAuthPresent" in condition.get("Bool", {})

    if actions & sensitive_actions and not has_mfa:
        return Finding(
            rule_id="IAM004",
            severity=Severity.MEDIUM,
            message=f"Sensitive action(s) {actions & sensitive_actions} allowed without MFA condition",
            statement=statement,
        )
    return None

ALL_RULES = [
    flag_wildcard_action_and_resource,
    flag_wildcard_action_only,
    flag_pass_role_without_condition,
    flag_no_mfa_on_sensitive_action,
]

def run_rules(statement: dict) -> list[Finding]:
    findings = []
    for rule_fn in ALL_RULES:
        result = rule_fn(statement)
        if result:
            findings.append(result)
    return findings