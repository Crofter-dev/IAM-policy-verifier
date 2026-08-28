# IAM Policy Verifier

A Python CLI (with an optional Flask dashboard) for auditing AWS IAM policies — flagging risky configurations, privilege-escalation chains, and unused permissions, with findings mapped to MITRE ATT&CK for SOC/IR-facing reporting.

Built as a defensive-tooling complement to [Sentinal](https://github.com/Crofter-dev/Sentinal) (an attacker-facing SSH honeypot) — together framing an offense-meets-defense cloud/network security portfolio.

## What it does

- **Static policy analysis** — scans IAM policy JSON (local files or a live AWS account) for known-bad patterns: wildcard actions/resources, unrestricted `iam:PassRole`, sensitive actions without MFA conditions.
- **Privilege escalation detection** — checks each principal's *combined* permissions (across all attached, inline, and group-inherited policies) against ~8 documented AWS IAM privilege-escalation techniques.
- **Unused permission detection** — cross-references granted permissions against IAM Access Advisor data to flag over-provisioned, never-used access (least-privilege reporting).
- **MITRE ATT&CK mapping** — every finding is tagged with its corresponding ATT&CK technique ID, name, and tactic.
- **Dashboard** — a lightweight Flask + vanilla-JS UI for browsing findings by severity.

## Architecture

```
policy_loader.py      Loads policies from a file or live AWS account;
                       groups them by principal (including group-inherited
                       and inline policies)
rules.py               Per-statement rule engine (wildcard grants, PassRole,
                        missing MFA conditions)
privesc_graph.py        Per-principal privilege-escalation technique matching
cloudtrail_check.py      Access Advisor-based unused-permission detection
attack_mapping.py       Maps internal rule/technique IDs to MITRE ATT&CK
main.py                 CLI entry point
dashboard.py            Flask app serving JSON findings + HTML dashboard
templates/dashboard.html  Frontend for the dashboard
```

## Usage

**Scan a local policy file:**
```bash
python main.py --file path/to/policy.json
```

**Scan a live AWS account:**
```bash
python main.py --aws --profile my-profile
```

**Run the dashboard:**
```bash
python dashboard.py
# visit http://localhost:5000
```

## Example output

```
Found 4 issue(s):

[CRITICAL] IAM001 - my-policy.json
    Statement grants '*' action on '*' resource (full admin access)

[HIGH] IAM002 - my-policy.json
    Statement grants wildcard '*' action

[HIGH] IAM003 - my-policy.json
    iam:PassRole granted without a restricting Condition

[MEDIUM] IAM004 - my-policy.json
    Sensitive action(s) {'iam:DeleteUser', 'iam:DeleteRole'} allowed without MFA condition
```

## Detected privilege escalation techniques

| Technique | Description |
|---|---|
| PE001 | `iam:CreatePolicyVersion` — create a new default policy version with arbitrary permissions |
| PE002 | `iam:SetDefaultPolicyVersion` — roll back to a prior, more permissive version |
| PE003 | `iam:CreateAccessKey` — create access keys for another user |
| PE004 | `iam:AttachUserPolicy` — attach an arbitrary (e.g. admin) policy to a user |
| PE005 | `iam:PassRole` + `ec2:RunInstances` — pass a privileged role to a new EC2 instance |
| PE006 | `iam:PassRole` + `lambda:CreateFunction`/`InvokeFunction` — pass a privileged role to Lambda |
| PE007 | `iam:UpdateLoginProfile` — reset another user's console password |
| PE008 | `iam:AttachGroupPolicy` — attach a privileged policy to an entire group |

Technique list based on the publicly documented AWS IAM privilege-escalation research by Rhino Security Labs.

## Requirements

- Python 3.10+
- `boto3` (for `--aws` mode and the dashboard's live-scan features)
- `flask` (for the dashboard)
- AWS credentials with `iam:GetAccountAuthorizationDetails`, `iam:ListUsers`, `iam:ListRoles`, and `iam:GenerateServiceLastAccessedDetails` permissions (for AWS-connected modes)

```bash
pip install boto3 flask
```

## Known limitations

- Unused-permission detection works at the AWS *service* level (e.g. `s3`, `ec2`), not the individual-action level, since IAM Access Advisor doesn't track historical usage per action.
- Privilege-escalation checks currently cover the most common documented techniques, not the full known set — additional techniques can be added to `PRIVESC_TECHNIQUES` in `privesc_graph.py`.
- The Access Advisor-based unused-permissions scan issues one job per principal and can be slow on accounts with many users/roles.

## Roadmap

- [x] Static rule engine
- [x] Privilege escalation graph (principal-level)
- [x] Live AWS account scanning
- [x] Unused permission detection (Access Advisor)
- [x] Flask dashboard
- [x] MITRE ATT&CK mapping
- [ ] Deduplicate wildcard-driven privesc findings into a single "full admin" finding
- [ ] Parallelize Access Advisor job polling for large accounts
