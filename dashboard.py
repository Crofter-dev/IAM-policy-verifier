from flask import Flask, render_template, jsonify
from policy import load_policies_from_aws, group_policies_by_principal, get_principal_arns, normalize_statements
from rules import run_rules
from privsec import run_privesc_scan

app = Flask(__name__)
_scan_cache = {}

def run_full_scan(profile:str = None):
    policies = load_policies_from_aws(profile=profile)
    policies_by_principal = group_policies_by_principal(profile=profile)
    principal_arns = get_principal_arns(profile=profile)

    rule_findings = []

    from attack import enrich_findings_with_attack

    rule_findings = enrich_findings_with_attack(rule_findings, id_field="rule_id")
    privesc_serialized = enrich_findings_with_attack(privesc_serialized, id_field="technique_id")

    for policy in policies:
        statements = normalize_statements(policy["Document"])
        for stmt in statements:
            for finding in run_rules(stmt):
                rule_findings.append({
                    "policy_name": policy["PolicyName"],
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "message": finding.message,
                })

    privsec_findings = run_privesc_scan(policies_by_principal)
    privsec_serialized = [{
            "technique_id": f.technique_id,
            "principal": f.principal,
            "description": f.description,
        }
        for f in privsec_findings
    ]

    unused_serialized = []

    return {
        "rule_findings": rule_findings,
        "privesc_findings": privsec_serialized,
        "unused_findings": unused_serialized,
    }

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/api/scan")
def api_scan():
    if "result" not in _scan_cache:
        _scan_cache["results"] = run_full_scan()
    return jsonify(_scan_cache["results"])

@app.route("/api/scan/refresh")
def api_scan_refresh():
    _scan_cache["results"] = run_full_scan()
    return jsonify(_scan_cache["results"])

if __name__ == "__main__":
    app.run(debug=True, port=5000)