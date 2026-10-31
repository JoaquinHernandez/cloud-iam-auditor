cat << 'EOF' > auditor/engine.py
import logging
from typing import Any, Dict, List, Set
from auditor.rules import ADMIN_WILDCARDS, PASSROLE_COMPUTE_SERVICES, UNILATERAL_ESCALATION_PRIMITIVES

logger = logging.getLogger("IAM-Engine")

class PolicyEvaluator:
    @staticmethod
    def _normalize_list(target: Any) -> List[str]:
        if target is None:
            return []
        if isinstance(target, list):
            return [str(item).strip() for item in target]
        return [str(target).strip()]

    @classmethod
    def evaluate_statement(cls, stmt: Dict[str, Any]) -> List[Dict[str, str]]:
        findings: List[Dict[str, str]] = []

        # Only evaluate statements granting permissions
        if stmt.get("Effect") != "Allow":
            return findings

        actions = cls._normalize_list(stmt.get("Action"))
        action_set: Set[str] = set(actions)
        action_set_lower: Set[str] = {a.lower() for a in action_set}

        # 1. Full Admin Wildcard Check
        for wildcard in ADMIN_WILDCARDS:
            if wildcard in action_set:
                findings.append({
                    "severity": "CRITICAL",
                    "rule_id": "SEC-IAM-001",
                    "title": "Unconstrained Administrator Wildcard",
                    "description": "Statement assigns unrestricted administrative action ('*')."
                })

        # 2. Unilateral Escalation Primitives Check
        for primitive, description in UNILATERAL_ESCALATION_PRIMITIVES.items():
            if primitive.lower() in action_set_lower or "*" in action_set:
                findings.append({
                    "severity": "HIGH",
                    "rule_id": "SEC-IAM-002",
                    "title": f"Unilateral Escalation: {primitive}",
                    "description": description
                })

        # 3. iam:PassRole Privilege Escalation Chain
        has_passrole = "iam:passrole" in action_set_lower or "*" in action_set
        if has_passrole:
            matched_services = [
                svc for svc in PASSROLE_COMPUTE_SERVICES
                if svc.lower() in action_set_lower or "*" in action_set
            ]
            if matched_services:
                findings.append({
                    "severity": "CRITICAL",
                    "rule_id": "SEC-IAM-003",
                    "title": "Toxic Escalation Chain: iam:PassRole + Compute",
                    "description": f"Enables lateral escalation via service compute execution: {', '.join(matched_services)}"
                })

        return findings

    @classmethod
    def evaluate_policy_document(cls, policy_doc: Dict[str, Any]) -> List[Dict[str, str]]:
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        findings: List[Dict[str, str]] = []
        for stmt in statements:
            findings.extend(cls.evaluate_statement(stmt))

        return findings
EOF
