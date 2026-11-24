import boto3
import json
import uuid
from datetime import datetime, timezone, timedelta


# ==========================================================
# AWS CLIENTS
# ==========================================================

ec2 = boto3.client("ec2")
cloudwatch = boto3.client("cloudwatch")
dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")

bedrock = boto3.client(
    "bedrock-runtime",
    region_name="us-west-1"
)


# ==========================================================
# CONFIGURATION
# ==========================================================

TABLE_NAME = "CloudGuardFindings"

SNS_TOPIC_ARN = (
    "arn:aws:sns:us-west-1:435159146259:"
    "CloudGuardCriticalAlerts"
)

BEDROCK_MODEL_ID = "us.amazon.nova-2-lite-v1:0"

table = dynamodb.Table(TABLE_NAME)


# ==========================================================
# RESOURCE NAME HELPERS
# ==========================================================

def get_group_name(group):

    for tag in group.get("Tags", []):

        if tag.get("Key") == "Name":
            return tag.get("Value")

    return group.get(
        "GroupName",
        "Unknown"
    )


def get_instance_name(instance):

    for tag in instance.get("Tags", []):

        if tag.get("Key") == "Name":
            return tag.get("Value")

    return instance["InstanceId"]


# ==========================================================
# BEDROCK AI ANALYSIS
# ==========================================================

def generate_ai_analysis(finding):

    prompt = f"""
You are CloudGuard AI, an AWS cloud security assistant.

Analyze the following AWS finding.

Finding title:
{finding['title']}

Severity:
{finding['severity']}

Category:
{finding['category']}

Resource type:
{finding['resourceType']}

Resource:
{finding['resourceName']}

Description:
{finding['description']}

Current recommendation:
{finding['recommendation']}

Return ONLY valid JSON.

Use exactly this structure:

{{
  "riskExplanation": "A concise explanation of why this finding is dangerous.",
  "businessImpact": "A concise explanation of the potential impact on an organization.",
  "remediation": "A concise practical remediation recommendation."
}}

Do not include markdown.
Do not include code fences.
Do not include any text outside the JSON object.
"""

    try:

        response = bedrock.converse(
            modelId=BEDROCK_MODEL_ID,

            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "text": prompt
                        }
                    ]
                }
            ],

            inferenceConfig={
                "maxTokens": 500,
                "temperature": 0.2,
                "topP": 0.9
            }
        )

        output_message = (
            response
            .get("output", {})
            .get("message", {})
        )

        content = output_message.get(
            "content",
            []
        )

        if not content:
            return None

        text = content[0].get(
            "text",
            ""
        ).strip()

        if not text:
            return None

        # Defensive cleanup in case the model
        # unexpectedly returns markdown fences.

        if text.startswith("```"):

            text = text.replace(
                "```json",
                ""
            )

            text = text.replace(
                "```",
                ""
            )

            text = text.strip()

        analysis = json.loads(text)

        return {
            "riskExplanation":
                analysis.get(
                    "riskExplanation",
                    ""
                ),

            "businessImpact":
                analysis.get(
                    "businessImpact",
                    ""
                ),

            "remediation":
                analysis.get(
                    "remediation",
                    ""
                )
        }

    except Exception as error:

        print(
            "Bedrock AI analysis failed:",
            str(error)
        )

        return None


# ==========================================================
# SAVE FINDING
# ==========================================================

def save_finding(
    scan_id,
    resource_id,
    resource_name,
    resource_type,
    rule_id,
    category,
    severity,
    title,
    description,
    recommendation,
    extra=None
):

    finding_id = (
        f"{rule_id}-"
        f"{uuid.uuid4().hex[:8]}"
    )

    finding = {
        "scanId":
            scan_id,

        "findingId":
            finding_id,

        "ruleId":
            rule_id,

        "resourceId":
            resource_id,

        "resourceName":
            resource_name,

        "resourceType":
            resource_type,

        "category":
            category,

        "severity":
            severity,

        "title":
            title,

        "description":
            description,

        "recommendation":
            recommendation,

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat()
    }

    if extra:
        finding.update(extra)

    # ------------------------------------------------------
    # BEDROCK AI ENRICHMENT
    # ------------------------------------------------------

    ai_analysis = generate_ai_analysis(
        finding
    )

    if ai_analysis:

        finding["aiAnalysis"] = (
            ai_analysis
        )

    else:

        finding["aiAnalysis"] = {
            "riskExplanation":
                (
                    "AI analysis was unavailable "
                    "for this scan."
                ),

            "businessImpact":
                (
                    "Review the finding using "
                    "standard AWS security practices."
                ),

            "remediation":
                recommendation
        }

    # ------------------------------------------------------
    # SAVE TO DYNAMODB
    # ------------------------------------------------------

    table.put_item(
        Item=finding
    )

    return finding


# ==========================================================
# SNS CRITICAL ALERT
# ==========================================================

def send_critical_alert(finding):

    ai = finding.get(
        "aiAnalysis",
        {}
    )

    subject = (
        "CloudGuard CRITICAL Alert - "
        f"{finding['title']}"
    )

    message = f"""
CLOUDGUARD AI
CRITICAL SECURITY ALERT

CloudGuard detected a critical security issue
in your AWS environment.

==================================================

SEVERITY

{finding['severity']}

==================================================

FINDING

{finding['title']}

Rule:
{finding['ruleId']}

==================================================

RESOURCE

Name:
{finding['resourceName']}

Resource ID:
{finding['resourceId']}

Resource Type:
{finding['resourceType']}

==================================================

DESCRIPTION

{finding['description']}

==================================================

RECOMMENDED ACTION

{finding['recommendation']}

==================================================

AI SECURITY ANALYSIS

Risk Explanation:

{ai.get('riskExplanation', 'Unavailable')}

Business Impact:

{ai.get('businessImpact', 'Unavailable')}

AI Recommended Remediation:

{ai.get('remediation', 'Unavailable')}

==================================================

SCAN INFORMATION

Scan ID:
{finding['scanId']}

Detected At:
{finding['timestamp']}

==================================================

CloudGuard AI
Cloud Security & Cost Intelligence
Powered by AWS Serverless Architecture
and Amazon Bedrock
"""

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,

        Subject=subject[:100],

        Message=message
    )


# ==========================================================
# SECURITY GROUP SCANNER
# ==========================================================

def scan_security_groups(scan_id):

    response = (
        ec2.describe_security_groups()
    )

    groups = response.get(
        "SecurityGroups",
        []
    )

    findings = []

    for group in groups:

        for permission in group.get(
            "IpPermissions",
            []
        ):

            protocol = permission.get(
                "IpProtocol"
            )

            from_port = permission.get(
                "FromPort"
            )

            to_port = permission.get(
                "ToPort"
            )

            ipv4_ranges = [
                item.get("CidrIp")

                for item in permission.get(
                    "IpRanges",
                    []
                )
            ]

            if "0.0.0.0/0" not in ipv4_ranges:
                continue

            # ==================================================
            # SEC-001
            # PUBLIC SSH
            # ==================================================

            if (
                protocol == "tcp"
                and from_port is not None
                and to_port is not None
                and from_port <= 22 <= to_port
            ):

                finding = save_finding(
                    scan_id,
                    group["GroupId"],
                    get_group_name(group),
                    "EC2_SECURITY_GROUP",
                    "SEC-001",
                    "SECURITY",
                    "CRITICAL",
                    "Public SSH Access Detected",
                    (
                        "SSH port 22 is accessible "
                        "from the public internet."
                    ),
                    (
                        "Restrict SSH access to "
                        "trusted administrative "
                        "IP addresses."
                    )
                )

                findings.append(finding)

            # ==================================================
            # SEC-002
            # PUBLIC RDP
            # ==================================================

            if (
                protocol == "tcp"
                and from_port is not None
                and to_port is not None
                and from_port <= 3389 <= to_port
            ):

                finding = save_finding(
                    scan_id,
                    group["GroupId"],
                    get_group_name(group),
                    "EC2_SECURITY_GROUP",
                    "SEC-002",
                    "SECURITY",
                    "CRITICAL",
                    "Public RDP Access Detected",
                    (
                        "RDP port 3389 is accessible "
                        "from the public internet."
                    ),
                    (
                        "Restrict RDP access to "
                        "trusted administrative "
                        "networks."
                    )
                )

                findings.append(finding)

            # ==================================================
            # SEC-003
            # ALL TRAFFIC PUBLIC
            # ==================================================

            if protocol == "-1":

                finding = save_finding(
                    scan_id,
                    group["GroupId"],
                    get_group_name(group),
                    "EC2_SECURITY_GROUP",
                    "SEC-003",
                    "SECURITY",
                    "CRITICAL",
                    "All Traffic Publicly Exposed",
                    (
                        "The security group allows "
                        "all protocols from the "
                        "public internet."
                    ),
                    (
                        "Remove unrestricted access "
                        "and allow only required "
                        "ports."
                    )
                )

                findings.append(finding)

    return groups, findings


# ==========================================================
# EC2 COST / UTILIZATION SCANNER
# ==========================================================

def scan_ec2_utilization(scan_id):

    response = ec2.describe_instances(
        Filters=[
            {
                "Name":
                    "instance-state-name",

                "Values":
                    ["running"]
            }
        ]
    )

    instances = []

    for reservation in response.get(
        "Reservations",
        []
    ):

        instances.extend(
            reservation.get(
                "Instances",
                []
            )
        )

    findings = []

    end_time = datetime.now(
        timezone.utc
    )

    start_time = (
        end_time -
        timedelta(hours=24)
    )

    for instance in instances:

        instance_id = (
            instance["InstanceId"]
        )

        metrics = (
            cloudwatch
            .get_metric_statistics(
                Namespace="AWS/EC2",

                MetricName=
                    "CPUUtilization",

                Dimensions=[
                    {
                        "Name":
                            "InstanceId",

                        "Value":
                            instance_id
                    }
                ],

                StartTime=
                    start_time,

                EndTime=
                    end_time,

                Period=3600,

                Statistics=[
                    "Average"
                ]
            )
        )

        datapoints = metrics.get(
            "Datapoints",
            []
        )

        if not datapoints:
            continue

        average_cpu = (
            sum(
                point["Average"]

                for point
                in datapoints
            )
            /
            len(datapoints)
        )

        if average_cpu < 5:

            finding = save_finding(
                scan_id,

                instance_id,

                get_instance_name(
                    instance
                ),

                "EC2_INSTANCE",

                "COST-001",

                "COST",

                "MEDIUM",

                (
                    "Potentially "
                    "Underutilized "
                    "EC2 Instance"
                ),

                (
                    f"Average CPU "
                    f"utilization over "
                    f"the last 24 hours "
                    f"is "
                    f"{average_cpu:.2f}%."
                ),

                (
                    "Review the workload "
                    "and consider "
                    "rightsizing or "
                    "stopping the instance "
                    "if it is no longer "
                    "required."
                ),

                {
                    "averageCpu":
                        str(
                            round(
                                average_cpu,
                                2
                            )
                        )
                }
            )

            findings.append(finding)

    return instances, findings


# ==========================================================
# LAMBDA HANDLER
# ==========================================================

def lambda_handler(event, context):

    scan_id = (
        "scan-" +
        uuid.uuid4().hex[:12]
    )

    print(
        "CloudGuard scan started:",
        scan_id
    )

    # ------------------------------------------------------
    # SECURITY SCAN
    # ------------------------------------------------------

    (
        security_groups,
        security_findings

    ) = scan_security_groups(
        scan_id
    )

    # ------------------------------------------------------
    # COST SCAN
    # ------------------------------------------------------

    (
        instances,
        cost_findings

    ) = scan_ec2_utilization(
        scan_id
    )

    findings = (
        security_findings +
        cost_findings
    )

    # ------------------------------------------------------
    # SEND SNS ALERTS
    # ------------------------------------------------------

    alerts_sent = 0

    alert_errors = []

    for finding in findings:

        if (
            finding.get(
                "severity"
            )
            == "CRITICAL"
        ):

            try:

                send_critical_alert(
                    finding
                )

                alerts_sent += 1

            except Exception as error:

                print(
                    "SNS notification failed:",
                    str(error)
                )

                alert_errors.append(
                    {
                        "findingId":
                            finding.get(
                                "findingId"
                            ),

                        "error":
                            str(error)
                    }
                )

    # ------------------------------------------------------
    # COUNT AI ANALYSES
    # ------------------------------------------------------

    ai_analyses_generated = 0

    for finding in findings:

        ai = finding.get(
            "aiAnalysis",
            {}
        )

        if (
            ai
            and ai.get(
                "riskExplanation"
            )
            !=
            "AI analysis was unavailable for this scan."
        ):

            ai_analyses_generated += 1

    # ------------------------------------------------------
    # FINAL RESULT
    # ------------------------------------------------------

    result = {

        "service":
            "CloudGuard AI",

        "scanId":
            scan_id,

        "status":
            "COMPLETED",

        "resourcesScanned": {

            "securityGroups":
                len(
                    security_groups
                ),

            "ec2Instances":
                len(
                    instances
                )
        },

        "summary": {

            "totalFindings":
                len(findings),

            "securityFindings":
                len(
                    security_findings
                ),

            "costFindings":
                len(
                    cost_findings
                ),

            "criticalAlertsSent":
                alerts_sent,

            "aiAnalysesGenerated":
                ai_analyses_generated
        },

        "findings":
            findings
    }

    if alert_errors:

        result[
            "alertErrors"
        ] = alert_errors

    print(
        "CloudGuard scan completed:",
        scan_id
    )

    return {
        "statusCode": 200,

        "body":
            json.dumps(result)
    }