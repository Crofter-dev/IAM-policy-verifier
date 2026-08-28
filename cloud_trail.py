import boto3
import time
from dataclasses import dataclass


@dataclass
class UnusedPermissionFinding:
    principal: str
    granted_actions: set
    used_actions: set
    unused_actions: set

def get_used_services_from_access_advisor(iam_client, principal_arn: str):
    job = iam_client.generate_service_last_accessed_details(Arn=principal_arn)
    job_id = job["JobId"]

    while True:
        result = iam_client.get_service_last_accessed_details(JobId=job_id)
        if result["JobStatus"] == "COMPLETED":
            break
        time.sleep(1)

    used_services = set()
    for entry in result.get("ServicesLastAccessed", []):
        if entry.get("LastAuthenticated"):
            used_services.add(entry["ServiceNamespace"])

    return used_services

def find_unused_permissions(
    principal_name: str,
    principal_arn: str,
    granted_actions: set,
    iam_client,
):
    used_services = get_used_services_from_access_advisor(iam_client, principal_arn)

    unused_actions = set()
    for action in granted_actions:
        if action == "*":
            continue
        service = action.split(":")[0]
        if service not in used_services:
            unused_actions.add(action)

    return UnusedPermissionFinding(
        principal=principal_name,
        granted_actions=granted_actions,
        used_actions=granted_actions - unused_actions,
        unused_actions=unused_actions,
    )

def run_unused_permissions_scan(policies_by_principal: dict, principal_arns: dict, profile: str = None):
    from privsec import extract_actions_for_principal

    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    iam = session.client("iam")

    findings = []
    for principal_name, policy_documents in policies_by_principal.items():
        arn = principal_arns.get(principal_name)
        if not arn:
            continue

        all_statements = []
        for doc in policy_documents:
            stmts = doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            all_statements.extend(stmts)

        granted_actions = extract_actions_for_principal(principal_name, all_statements)
        finding = find_unused_permissions(principal_name, arn, granted_actions, iam)
        findings.append(finding)

    return findings