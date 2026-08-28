import json
import boto3
import pathlib

def file_policy(filepath:str):
    path = pathlib.Path(filepath)
    if not path.exists():
        return FileNotFoundError(f"File not found: {filepath}")
    with open(path, "r") as f:
        return json.load(f)

def aws_policy(profile: str = None):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    iam = session.client("iam")
    policies = []
    paginator = iam.get_paginator("get_account_authorization_details")

    for page in paginator.paginate(Filter=["LocalManagedPolicy", "AWSManagedPolicy"]):
        for policy in page.get("Policies", []):
            default_version_id = policy["DefaultVersionId"]
            for version in policy.get("PolicyVersionList", []):
                if version["VersionId"] == default_version_id:
                    policies.append({
                        "PolicyName": policy["PolicyName"],
                        "Arn": policy["Arn"],
                        "Document": version["Document"],
                    })
    return policies
    
def group_policies_by_principal(profile: str = None) -> dict:
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    iam = session.client("iam")
    policy_documents_by_arn = {}
    paginator = iam.get_paginator("get_account_authorization_details")

    pages = list(paginator.paginate())  

    for page in pages:
        for policy in page.get("Policies", []):
            default_version_id = policy["DefaultVersionId"]
            for version in policy.get("PolicyVersionList", []):
                if version["VersionId"] == default_version_id:
                    policy_documents_by_arn[policy["Arn"]] = version["Document"]

    policies_by_principal = {}

    for page in pages:
        for user in page.get("UserDetailList", []):
            principal_name = user["UserName"]
            docs = []

            for attached in user.get("AttachedManagedPolicies", []):
                arn = attached["PolicyArn"]
                if arn in policy_documents_by_arn:
                    docs.append(policy_documents_by_arn[arn])

            for inline in user.get("UserPolicyList", []):
                docs.append(inline["PolicyDocument"])

            if docs:
                policies_by_principal.setdefault(principal_name, []).extend(docs)

        for role in page.get("RoleDetailList", []):
            principal_name = role["RoleName"]
            docs = []

            for attached in role.get("AttachedManagedPolicies", []):
                arn = attached["PolicyArn"]
                if arn in policy_documents_by_arn:
                    docs.append(policy_documents_by_arn[arn])

            for inline in role.get("RolePolicyList", []):
                docs.append(inline["PolicyDocument"])

            if docs:
                policies_by_principal.setdefault(principal_name, []).extend(docs)

    return policies_by_principal

def normalize(policy_document:dict):
    statements = policy_document.get("Statements", [])
    if isinstance(statements, dict):
        statements = [statements]
    return statements

def get_principal_arns(profile: str = None):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    iam = session.client("iam")

    principal_arns = {}

    user_paginator = iam.get_paginator("list_users")
    for page in user_paginator.paginate():
        for user in page.get("Users", []):
            principal_arns[user["UserName"]] = user["Arn"]

    role_paginator = iam.get_paginator("list_roles")
    for page in role_paginator.paginate():
        for role in page.get("Roles", []):
            principal_arns[role["RoleName"]] = role["Arn"]

    return principal_arns

def load_policies_from_aws(profile: str = None):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    iam = session.client("iam")

    policies = []
    paginator = iam.get_paginator("get_account_authorization_details")

    for page in paginator.paginate(Filter=["LocalManagedPolicy", "AWSManagedPolicy"]):
        for policy in page.get("Policies", []):
            default_version_id = policy["DefaultVersionId"]
            for version in policy.get("PolicyVersionList", []):
                if version["VersionId"] == default_version_id:
                    policies.append({
                        "PolicyName": policy["PolicyName"],
                        "Arn": policy["Arn"],
                        "Document": version["Document"],
                    })
    return policies
