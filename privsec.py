from dataclasses import dataclass

PRIVESC_TECHNIQUES = {
    "PE001_CreatePolicyVersion": {
        "required_actions": {"iam:CreatePolicyVersion"},
        "description": "Can create a new default policy version with arbitrary permissions",
    },
    "PE002_SetDefaultPolicyVersion": {
        "required_actions": {"iam:SetDefaultPolicyVersion"},
        "description": "Can roll back to a prior, more permissive policy version",
    },
    "PE003_CreateAccessKey": {
        "required_actions": {"iam:CreateAccessKey"},
        "description": "Can create access keys for another user, effectively becoming them",
    },
    "PE004_AttachUserPolicy": {
        "required_actions": {"iam:AttachUserPolicy"},
        "description": "Can attach AdministratorAccess (or any policy) to themselves or another user",
    },
    "PE005_PassRoleEC2": {
        "required_actions": {"iam:PassRole", "ec2:RunInstances"},
        "description": "Can pass a privileged role to a new EC2 instance and access it via that role",
    },
    "PE006_PassRoleLambda": {
        "required_actions": {"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"},
        "description": "Can pass a privileged role to a Lambda function and invoke it",
    },
    "PE007_UpdateLoginProfile": {
        "required_actions": {"iam:UpdateLoginProfile"},
        "description": "Can set/reset the console password of another user",
    },
    "PE008_AttachGroupPolicy": {
        "required_actions": {"iam:AttachGroupPolicy"},
        "description": "Can attach a privileged policy to a group, escalating everyone in it",
    },
}

@dataclass
class PrivEscFinding:
    technique_id: str
    principal: str
    matched_actions: set
    description: str

def extract_actions_for_principal(principal_name: str, statements: list[dict]) -> set:
    actions = set()
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        stmt_actions = stmt.get("Action", [])
        if isinstance(stmt_actions, str):
            stmt_actions = [stmt_actions]
        actions.update(stmt_actions)
    return actions

def check_privesc_techniques(principal_name: str, granted_actions: set) -> list[PrivEscFinding]:
    findings = []

    has_wildcard = "*" in granted_actions or "iam:*" in granted_actions

    for technique_id, technique in PRIVESC_TECHNIQUES.items():
        required = technique["required_actions"]

        if has_wildcard or required.issubset(granted_actions):
            findings.append(PrivEscFinding(
                technique_id=technique_id,
                principal=principal_name,
                matched_actions=required if not has_wildcard else {"*"},
                description=technique["description"],
            ))

    return findings

def build_principal_action_map(policies_by_principal: dict) -> dict:
    principal_actions = {}
    for principal_name, policy_documents in policies_by_principal.items():
        all_statements = []
        for doc in policy_documents:
            stmts = doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            all_statements.extend(stmts)

        principal_actions[principal_name] = extract_actions_for_principal(principal_name, all_statements)

    return principal_actions

def run_privesc_scan(policies_by_principal: dict) -> list[PrivEscFinding]:
    principal_actions = build_principal_action_map(policies_by_principal)
    all_findings = []

    for principal_name, actions in principal_actions.items():
        findings = check_privesc_techniques(principal_name, actions)
        all_findings.extend(findings)

    return all_findings