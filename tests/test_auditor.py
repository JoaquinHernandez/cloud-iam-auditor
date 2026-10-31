cat << 'EOF' > tests/__init__.py
EOF

cat << 'EOF' > tests/test_auditor.py
import json
import pytest
from auditor.engine import PolicyEvaluator

def load_fixture(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def test_compliant_least_privilege():
    doc = load_fixture("fixtures/compliant_least_privilege.json")
    findings = PolicyEvaluator.evaluate_policy_document(doc)
    assert len(findings) == 0

def test_toxic_passrole_escalation():
    doc = load_fixture("fixtures/toxic_passrole.json")
    findings = PolicyEvaluator.evaluate_policy_document(doc)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-IAM-003"
    assert findings[0]["severity"] == "CRITICAL"

def test_wildcard_detection():
    doc = load_fixture("fixtures/toxic_wildcard.json")
    findings = PolicyEvaluator.evaluate_policy_document(doc)
    rule_ids = [f["rule_id"] for f in findings]
    assert "SEC-IAM-001" in rule_ids
    assert "SEC-IAM-002" in rule_ids

def test_unilateral_key_creation():
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:CreateAccessKey"],
                "Resource": "*"
            }
        ]
    }
    findings = PolicyEvaluator.evaluate_policy_document(doc)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-IAM-002"
    assert "CreateAccessKey" in findings[0]["title"]
EOF
