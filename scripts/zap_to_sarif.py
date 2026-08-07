import json, os, sys, re

workspace   = os.environ.get("GITHUB_WORKSPACE", ".")
report_file = os.path.join(workspace, "zap_report.json")
sarif_file  = os.path.join(workspace, "zap_sarif.sarif")

print(f"Workspace:   {workspace}")
print(f"Report file: {report_file}")
print(f"SARIF file:  {sarif_file}")

def strip_html(text):
    if not text:
        return "https://www.zaproxy.org/"
    urls = re.findall(r'https?://[^\s<>"\']+', text)
    if urls:
        return urls[0].rstrip('/')
    clean = re.sub(r'<[^>]+>', '', text).strip()
    return clean if clean.startswith('http') else "https://www.zaproxy.org/"

sarif = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{
        "tool": {"driver": {"name": "OWASP ZAP", "version": "2.x", "rules": []}},
        "results": []
    }]
}

if not os.path.exists(report_file) or os.path.getsize(report_file) == 0:
    print(f"WARNING: ZAP JSON not found or empty")
    print(f"Files in workspace: {os.listdir(workspace)}")
    with open(sarif_file, "w") as f:
        json.dump(sarif, f)
    sys.exit(0)

with open(report_file) as f:
    zap = json.load(f)

rules, results = {}, []
for site in zap.get("site", []):
    for alert in site.get("alerts", []):
        rule_id   = alert.get("pluginid", "unknown")
        rule_name = alert.get("alert", "Unknown")
        severity  = {"3": "error", "2": "warning", "1": "note", "0": "none"}.get(
                        str(alert.get("riskcode", "1")), "warning")
        help_uri  = strip_html(alert.get("reference", ""))

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_name,
                "shortDescription": {"text": rule_name},
                "helpUri": help_uri,
                "properties": {"problem.severity": severity}
            }

        for instance in alert.get("instances", [{}]):
            raw_uri  = instance.get("uri", site.get("@name", "unknown"))
            # GitHub Code Scanning requires a real source file path.
            # DAST results have no source file — use app_fixed.py as the
            # anchor point and record the scanned URL in the message.
            results.append({
                "ruleId": rule_id,
                "level": severity,
                "message": {
                    "text": f"{alert.get('desc', rule_name)} [Scanned URL: {raw_uri}]"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "src/python/app_fixed.py",
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": 1
                        }
                    }
                }]
            })

sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules.values())
sarif["runs"][0]["results"] = results
with open(sarif_file, "w") as f:
    json.dump(sarif, f, indent=2)
print(f"SARIF written: {len(results)} findings, {len(rules)} rules")
