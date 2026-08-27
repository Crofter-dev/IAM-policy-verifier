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

def normalize(policy_document:dict):
    statements = policy_document.get("Statements", [])
    if isinstance(statements, dict):
        statements = [statements]
    return statements