cat << 'EOF' > main.py
import argparse
import json
import logging
import sys
from typing import Dict, List
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from auditor.engine import PolicyEvaluator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("IAM-Auditor")

def scan_file(file_path: str) -> bool:
    logger.info(f"Analyzing static policy document: {file_path}")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except Exception as e:
        logger.error(f"Failed to read file {file_path}: {e}")
        return False

    findings = PolicyEvaluator.evaluate_policy_document(doc)
    if not findings:
        print("[+] PASS: Policy adheres to least-privilege baseline. No escalation paths identified.")
        return True

    print(f"\n[-] VIOLATION: {len(findings)} security issue(s) detected in {file_path}:")
    for f in findings:
        print(f"    [{f['severity']}] {f['rule_id']} - {f['title']}")
        print(f"        -> {f['description']}")
    return False

def scan_live_aws_roles():
    logger.info("Connecting to AWS IAM API...")
    try:
        iam = boto3.client("iam")
        paginator = iam.get_paginator("list_roles")
    except (NoCredentialsError, ClientError) as e:
        logger.error(f"Authentication failure: {e}")
        sys.exit(1)

    total_scanned = 0
    total_violations = 0

    for page in paginator.paginate():
        for role in page.get("Roles", []):
            role_name = role["RoleName"]
            if role_name.startswith("aws-service-role"):
                continue

            total_scanned += 1
            attached = iam.list_attached_role_policies(RoleName=role_name)

            for policy in attached.get("AttachedPolicies", []):
                policy_arn = policy["PolicyArn"]
                try:
                    meta = iam.get_policy(PolicyArn=policy_arn)
                    version_id = meta["Policy"]["DefaultVersionId"]
                    policy_version = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=version_id
                    )
                    doc = policy_version["PolicyVersion"]["Document"]
                    findings = PolicyEvaluator.evaluate_policy_document(doc)

                    if findings:
                        total_violations += len(findings)
                        print(f"\n[!] Target Role: {role_name}")
                        print(f"    Attached Policy: {policy['PolicyName']} ({policy_arn})")
                        for f in findings:
                            print(f"    [{f['severity']}] {f['rule_id']}: {f['title']}")
                            print(f"        -> {f['description']}")
                except ClientError as e:
                    logger.warning(f"Could not read {policy_arn}: {e}")

    print("\n" + "=" * 50)
    print(f"Scan Complete: {total_scanned} custom roles evaluated.")
    print(f"Total Policy Findings: {total_violations}")
    print("=" * 50)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enterprise Cloud IAM Escalation & Audit Tool")
    parser.add_argument("--file", "-f", help="Path to local IAM Policy JSON file to validate.")
    parser.add_argument("--live", "-l", action="store_true", help="Execute active enumeration against current AWS credentials.")
    args = parser.parse_args()

    if args.file:
        success = scan_file(args.file)
        sys.exit(0 if success else 1)
    elif args.live:
        scan_live_aws_roles()
    else:
        parser.print_help()
EOF
