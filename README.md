

# Cloud IAM Least-Privilege & Escalation Auditor

<img width="1024" height="572" alt="image" src="https://github.com/user-attachments/assets/64cfd7ed-b8a8-4c18-b1de-e829d5858eb8" />


![AWS IAM](https://img.shields.io/badge/AWS_Security-IAM_Governance-orange?style=for-the-badge&logo=amazon-aws)
![Testing](https://img.shields.io/badge/Coverage-100%25_Passing-brightgreen?style=for-the-badge&logo=pytest)
![Compliance](https://img.shields.io/badge/Compliance-CIS_AWS_Benchmark-blue?style=for-the-badge)

A security audit engine that inspects AWS IAM policies for privilege escalation paths, toxic permission chains, and administrative wildcards.
MITRE ATT&CK Matrix Alignment
T1078.004 (Cloud Accounts): Detects policies permitting secondary credential generation via iam:CreateAccessKey or iam:CreateLoginProfile.

T1098 (Account Manipulation): Detects unauthorized permission additions via iam:AttachRolePolicy or iam:PutUserPolicy.

T1053.005 (Scheduled Task): Flags compute-execution boundaries where roles can be passed to execute workloads with elevated identities.

2. Rule Catalog
Rule ID	Severity	Vector Description	MITRE Mapping
SEC-IAM-001	CRITICAL	Unconstrained administrative wildcard (* or *:*)	T1078.004
SEC-IAM-002	HIGH	Direct credential injection or policy elevation primitive	T1098
SEC-IAM-003	CRITICAL	iam:PassRole combined with compute provisioning rights	T1078.004
3. Quickstart & Verification
Local Offline Scan
Bash
# Evaluate compliant policy
python main.py --file fixtures/compliant_least_privilege.json

# Evaluate toxic PassRole policy (terminates with exit code 1)
python main.py --file fixtures/toxic_passrole.json
Live AWS Account Audit
Bash
# Requires configured AWS credentials (AWS_PROFILE or environment keys)
python main.py --live
Run Test Suite
Bash
pytest tests/ -v
EOF


---

### Step 8: Initialize Git & Commit

Commit all files into version control:

```bash
git init
git add .
git commit -m "feat(audit): implement enterprise cloud IAM privilege escalation engine"
git branch -M main

# Link to your remote GitHub repository:
# git remote add origin https://github.com/<your-username>/cloud-iam-auditor.git
# git push -u origin main
---

## 1. Threat Model & Logic Flow

```mermaid
flowchart TD
    A[IAM Policy Document] --> B[Statement Normalizer]
    B --> C{Statement Effect}
    C -->|Deny| Z[Ignore Statement]
    C -->|Allow| D[Extract Action AST]
    
    D --> E{Action Analysis}
    E -->|Contains * or *:*| F[Rule SEC-IAM-001: Admin Wildcard]
    E -->|Matches Unilateral Actions| G[Rule SEC-IAM-002: Direct Escalation]
    E -->|iam:PassRole + Compute API| H[Rule SEC-IAM-003: Toxic Chain]
    
    F --> I[Generate Violation Report]
    G --> I
    H --> I

