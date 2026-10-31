cat << 'EOF' > auditor/__init__.py
"""Cloud IAM Auditor Package."""
__version__ = "1.0.0"
EOF

cat << 'EOF' > auditor/rules.py
"""
IAM Escalation Ruleset.
Detects unilateral escalation primitives and high-risk action pairs.
"""

from typing import Dict, List, Set

# Full Administrative Wildcards
ADMIN_WILDCARDS: Set[str] = {"*", "*:*"}

# Unilateral Escalation: Single actions that allow immediate administrative control
UNILATERAL_ESCALATION_PRIMITIVES: Dict[str, str] = {
    "iam:CreateAccessKey": "Can provision permanent access keys for arbitrary target identities (T1098).",
    "iam:CreateLoginProfile": "Can generate web console passwords for dormant/headless users (T1098).",
    "iam:UpdateLoginProfile": "Can reset console credentials for target administrator accounts (T1098).",
    "iam:AttachUserPolicy": "Can attach AdministratorAccess to self or target entities (T1098).",
    "iam:AttachRolePolicy": "Can attach AdministratorAccess to assumeable roles (T1098).",
    "iam:PutUserPolicy": "Can write arbitrary inline administrative policies into users (T1098).",
    "iam:PutRolePolicy": "Can write arbitrary inline administrative policies into roles (T1098).",
    "iam:SetDefaultPolicyVersion": "Can roll back policy states to historically vulnerable versions (T1098).",
    "iam:CreatePolicyVersion": "Can publish high-privilege versions exceeding administrative thresholds (T1098)."
}

# Combinator Escalation: iam:PassRole chained with execution-capable service APIs
PASSROLE_COMPUTE_SERVICES: List[str] = [
    "ec2:RunInstances",
    "lambda:CreateFunction",
    "lambda:CreateEventSourceMapping",
    "glue:CreateDevEndpoint",
    "cloudformation:CreateStack",
    "ecs:RunTask"
]
EOF
