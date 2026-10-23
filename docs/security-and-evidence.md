# Security boundaries and review evidence

The Excel decision field is a record of review, not authentication. A person typing “Approved” into a workbook does not authorize AWS execution. The generated document uses the SSM `aws:approve` step with an embedded IAM approver ARN. The plan hash identifies reviewed content; it is not a digital signature and does not authenticate its author.

Separate these duties with your existing IAM/SSO controls:

| Identity | Intended access | Boundary |
| --- | --- | --- |
| Inventory operator | EC2 DescribeInstances; SSM SendCommand on the publisher-owned PHP-Inventory document/selected instance ARNs; GetCommandInvocation; STS identity | No AWS-RunShellScript access, document editing or command parameters. Pin the numeric inventory document version. |
| Document publisher | Create/review the exact per-change Automation version | Trusted administrator. Must not be available to ordinary change requesters. |
| Change requester | StartAutomationExecution only for approved document ARNs/versions; read execution | No UpdateDocument, direct SendCommand, approval role assumption or broader PassRole. |
| Approver | SSM SendAutomationSignal for authorized executions, read evidence | Distinct organizational principal from requester; the code cannot establish who is behind an IAM role. |
| Automation role | SSM SendCommand to AWS-RunShellScript and exact canary instance ARN; command/execution read permissions | Trust only ssm.amazonaws.com; constrain source account and Automation execution ARN with SourceAccount/SourceArn. No broad administrator policy. |

The example does not create these policies or certify their enforcement. Validate resource/action support with your IAM administrator, Access Analyzer and a staging execution. Limit iam:PassRole to the reviewed Automation role and the SSM service where it is required. A publisher, approver or operator with broader existing permissions can bypass application-level checks; review effective permissions, not just this runbook.

The default Run Command API returns only part of large stdout/stderr streams. Inventory deliberately fails closed for oversized JSON. Package-install output can be longer: configure your approved SSM output destination/logging and retention for full transaction evidence. CloudTrail/SSM recording is not a guarantee of long-term retention. Export execution history into your controlled evidence store before it expires. Use encryption, restricted access and your organization's retention policy. Do not commit real inventory, instance IDs, account IDs, ticket content or SSM output to this public repository.

The remote patch script reads existing package state again immediately before upgrading. This detects ordinary drift; it is not a distributed lock against an independent administrator or configuration agent. Suspend competing patch automation during the approved window. There is no automatic retry of package mutation in this code. Reassess partial results before retrying.

Before closing a change, retain:

1. Complete target scope and any unresolved coverage gaps.
2. Exact vendor advisory/package evidence for both October 21 CVEs; review subsequent advisories separately.
3. Raw inventory SHA256, reviewed plan, published document/version/hash and execution ID.
4. Approval identity/time and change-ticket record; backup and tested rollback reference.
5. Package transaction output, before/after runtime inventory and verified service restarts.
6. Application/ALB health checks and any residual exceptions with named owner and expiry.

An active service does not prove it is serving the expected PHP code. A fixed binary on disk does not prove every existing worker was replaced. Package version evidence alone also does not establish runtime configuration, exploitability, absence of compromise or compliance with an external standard.
