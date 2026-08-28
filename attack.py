from dataclasses import dataclass

@dataclass
class AttackMapping:
    technique_id:str
    technique_name:str
    tactic:str

ATTACK_MAP = {
    "IAM001": AttackMapping("T1078.004", "Valid Accounts: Cloud Accounts", "Defense Evasion, Persistence, Privilege Escalation, Initial Access"),
    "IAM002": AttackMapping("T1078.004", "Valid Accounts: Cloud Accounts", "Defense Evasion, Persistence, Privilege Escalation, Initial Access"),
    "IAM003": AttackMapping("T1548.005", "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access", "Privilege Escalation, Defense Evasion"),
    "IAM004": AttackMapping("T1556.006", "Modify Authentication Process: Multi-Factor Authentication", "Credential Access, Defense Evasion, Persistence"),
    "PE001_CreatePolicyVersion": AttackMapping("T1098.003", "Account Manipulation: Additional Cloud Roles", "Persistence, Privilege Escalation"),
    "PE002_SetDefaultPolicyVersion": AttackMapping("T1098.003", "Account Manipulation: Additional Cloud Roles", "Persistence, Privilege Escalation"),
    "PE003_CreateAccessKey": AttackMapping("T1098.001", "Account Manipulation: Additional Cloud Credentials", "Persistence, Privilege Escalation"),
    "PE004_AttachUserPolicy": AttackMapping("T1098.003", "Account Manipulation: Additional Cloud Roles", "Persistence, Privilege Escalation"),
    "PE005_PassRoleEC2": AttackMapping("T1548.005", "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access", "Privilege Escalation, Defense Evasion"),
    "PE006_PassRoleLambda": AttackMapping("T1548.005", "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access", "Privilege Escalation, Defense Evasion"),
    "PE007_UpdateLoginProfile": AttackMapping("T1098", "Account Manipulation", "Persistence"),
    "PE008_AttachGroupPolicy": AttackMapping("T1098.003", "Account Manipulation: Additional Cloud Roles", "Persistence, Privilege Escalation"),
}

def get_attack_mapping(rule_or_technique_id:str):
    return ATTACK_MAP.get(rule_or_technique_id)

def enrich_findings_with_attack(findings:list, id_field:str="rule_id"):
    enriched = []
    for finding in findings:
        fid = getattr(finding, id_field, None) or finding.get(id_field)
        mapping = get_attack_mapping(fid)

        base = finding.__dict__ if hasattr(finding, "__dict__") else dict(finding)
        base["attack_technique_id"] = mapping.technique_id if mapping else None
        base["attack_technique_name"] = mapping.technique_name if mapping else None
        base["attack_tactic"] = mapping.tactic if mapping else None

        enriched.append(base)

    return enriched