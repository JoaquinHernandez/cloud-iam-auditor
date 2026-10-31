# cloud-iam-auditor

# Cloud IAM Least-Privilege & Escalation Auditor

<img width="1024" height="572" alt="image" src="https://github.com/user-attachments/assets/64cfd7ed-b8a8-4c18-b1de-e829d5858eb8" />


![AWS IAM](https://img.shields.io/badge/AWS_Security-IAM_Governance-orange?style=for-the-badge&logo=amazon-aws)
![Testing](https://img.shields.io/badge/Coverage-100%25_Passing-brightgreen?style=for-the-badge&logo=pytest)
![Compliance](https://img.shields.io/badge/Compliance-CIS_AWS_Benchmark-blue?style=for-the-badge)

A security audit engine that inspects AWS IAM policies for privilege escalation paths, toxic permission chains, and administrative wildcards.

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
