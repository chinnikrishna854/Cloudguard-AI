# CloudGuard AI

### AI-Powered Cloud Security & Cost Intelligence Platform

CloudGuard AI is a serverless AWS-based platform that analyzes cloud resources for security risks and cost optimization opportunities.

It combines deterministic cloud-security rules with Amazon Bedrock generative AI to detect infrastructure issues, explain their potential impact, recommend remediation, store findings, send critical alerts, and present results through a secure web dashboard.

---

## Live Application

CloudGuard AI is deployed on AWS using Amazon S3 and Amazon CloudFront.

**Application URL:**

https://d1bj62ku0cac8e.cloudfront.net/

Authentication is handled using Amazon Cognito.

---

# Problem

Public cloud environments can become difficult to manage as infrastructure grows.

Development teams may accidentally:

- Expose administrative ports to the public internet
- Maintain overly permissive security groups
- Leave underutilized compute resources running
- Accumulate unnecessary cloud costs
- Miss important security configuration problems
- Struggle to interpret raw cloud configuration data

CloudGuard AI converts cloud infrastructure information into prioritized and actionable findings.

The platform focuses on three questions:

1. What is wrong?
2. Why does it matter?
3. What should be done about it?

---

# Solution

CloudGuard AI scans selected AWS resources and generates findings related to:

- Cloud security
- Resource utilization
- Cost optimization

The system uses deterministic rules for detection and Amazon Bedrock for contextual AI analysis.

For example, if an EC2 security group exposes SSH port 22 to:

```text
0.0.0.0/0
