import boto3
import json
from decimal import Decimal
from collections import defaultdict

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("CloudGuardFindings")


def decimal_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError


def lambda_handler(event, context):

    response = table.scan()
    all_findings = response.get("Items", [])

    # Handle pagination in case the table grows beyond 1 MB.
    while "LastEvaluatedKey" in response:
        response = table.scan(
            ExclusiveStartKey=response["LastEvaluatedKey"]
        )
        all_findings.extend(response.get("Items", []))

    if not all_findings:
        result = {
            "service": "CloudGuard AI",
            "status": "SUCCESS",
            "scanId": None,
            "totalFindings": 0,
            "severityCounts": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0
            },
            "categoryCounts": {
                "SECURITY": 0,
                "COST": 0
            },
            "findings": []
        }

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps(result)
        }

    # Group findings by scanId.
    scans = defaultdict(list)

    for finding in all_findings:
        scan_id = finding.get("scanId")

        if scan_id:
            scans[scan_id].append(finding)

    # Determine the newest scan using finding timestamps.
    latest_scan_id = max(
        scans,
        key=lambda scan_id: max(
            item.get("timestamp", "")
            for item in scans[scan_id]
        )
    )

    findings = scans[latest_scan_id]

    # Newest finding first.
    findings.sort(
        key=lambda item: item.get("timestamp", ""),
        reverse=True
    )

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    category_counts = {
        "SECURITY": 0,
        "COST": 0
    }

    for finding in findings:

        severity = finding.get("severity")
        category = finding.get("category")

        if severity in severity_counts:
            severity_counts[severity] += 1

        if category in category_counts:
            category_counts[category] += 1

    result = {
        "service": "CloudGuard AI",
        "status": "SUCCESS",
        "scanId": latest_scan_id,
        "totalFindings": len(findings),
        "severityCounts": severity_counts,
        "categoryCounts": category_counts,
        "findings": findings
    }

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(
            result,
            default=decimal_default
        )
    }