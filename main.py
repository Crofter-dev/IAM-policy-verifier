import argparse
import sys
from policy import (load_policy_from_file,
    load_policies_from_aws,
    normalize_statements,)

from rules import run_rules, Severity
from security.IAM_POLICY import cloud_trail

SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[91m",  
    Severity.HIGH: "\033[93m",      
    Severity.MEDIUM: "\033[94m",    
    Severity.LOW: "\033[90m",       
}
RESET = "\033[0m"

def analyze_policy(policy_name: str, policy_document: dict):
    statements = normalize_statements(policy_document)
    all_findings = []

    for stmt in statements:
        findings = run_rules(stmt)
        for f in findings:
            all_findings.append((policy_name, f))

    return all_findings

def print_report(all_findings: list):
    if not all_findings:
        print("[+] No issues found.")
        return

    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    all_findings.sort(key=lambda pair: severity_order[pair[1].severity])

    print(f"\nFound {len(all_findings)} issue(s):\n")
    for policy_name, finding in all_findings:
        color = SEVERITY_COLORS[finding.severity]
        print(f"{color}[{finding.severity.value}]{RESET} {finding.rule_id} — {policy_name}")
        print(f"{finding.message}")
        print()

def main():
    parser = argparse.ArgumentParser(
        description="IAM Policy Verifier — audit AWS IAM policies for risky configurations."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", help="Path to a local IAM policy JSON file")
    source.add_argument("--aws", action="store_true", help="Pull policies from a live AWS account")
    parser.add_argument("--profile", help="AWS profile name (used with --aws)", default=None)

    args = parser.parse_args()
    all_findings = []

    if args.file:
        policy_document = load_policy_from_file(args.file)
        all_findings = analyze_policy(args.file, policy_document)

    elif args.aws:
        try:
            policies = load_policies_from_aws(profile=args.profile)
        except Exception as e:
            print(f"[-] Failed to fetch policies from AWS: {e}")
            sys.exit(1)

        for policy in policies:
            findings = analyze_policy(policy["PolicyName"], policy["Document"])
            all_findings.extend(findings)

    elif args.unused:
        policies_by_principal = policy.group_policies_by_principal(profile=args.profile)
        principal_arns = policy.get_principal_arns(profile=args.profile)  
        findings = cloud_trail.run_unused_permissions_scan(policies_by_principal, principal_arns, profile=args.profile)

    print_report(all_findings)

if __name__ == "__main__":
    main()