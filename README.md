# PHP inventory and reviewed remediation with AWS Systems Manager

Find PHP on mixed Linux EC2 instances, export evidence for Excel review, then prepare a **separate, single-host, approval-gated patch change**. No live AWS account has been scanned or patched as part of this example.

The collector is deliberately small. It uses SSM Run Command and Python's standard library on the host. It inventories dpkg/RPM packages and PHP CLI/FPM/CGI binaries in known paths. No SSH access or application secrets are required. Containers, arbitrary custom locations, FrankenPHP, LiteSpeed and loaded Apache modules require additional review. A negative result means **not detected in this scope**, not proof that PHP is absent everywhere.

## What this checks

The [PHP advisory of 21 October 2026](https://www.php.net/archive/2026.php#2026-10-21-5) identifies CVE-2026-109618 and CVE-2026-109619. Its upstream fix versions are 8.2.35, 8.3.36, 8.4.27 and 8.5.12. This is a version-specific assessment, not a general vulnerability scanner.

Linux vendors can backport fixes into older package versions. The script deliberately returns `VENDOR_FIX_REVIEW` instead of declaring those packages unpatched. Review the exact OS release, package version and advisory for **both CVEs**. The tool does not download or interpret vendor advisory feeds and does not automatically verify a URL entered by a reviewer.

**Follow-up advisory:** PHP published additional [session upload progress guidance on 23 October](https://www.php.net/archive/2026.php#2026-10-23-1), referring to CVE-2026-115560 and particular runtime configuration conditions. The version thresholds above do not assess that follow-up. Review its configuration guidance separately; this tool never changes PHP configuration automatically.

| Report state | Meaning |
| --- | --- |
| `FIX_LEVEL_DETECTED` | Observed core packages/binaries meet the upstream fix floor for the two October 21 CVEs. Loaded worker and application checks are still needed. |
| `VENDOR_FIX_REVIEW` | Lower upstream version; vendor backport evidence is required. |
| `UNSUPPORTED_BRANCH_REVIEW` | Outside the supported branch map, including upstream EOL releases. Obtain vendor support evidence or plan an upgrade. |
| `VERSION_REVIEW` | Evidence cannot establish a core runtime fix level. |
| `NOT_DETECTED_IN_SCOPE` | No PHP evidence in the package database/known executable paths searched. |
| `SCAN_INCOMPLETE` | Offline/unmanaged host, unsupported platform, permission failure, missing Python, malformed/oversized output or collector error. Never a clean result. |

## 1. Try the offline review

From this directory:

```bash
python3 inventory.py --fixture examples/inventory-demo.json --output reports/demo
# Exit 2 is expected: the seven fictional hosts include two incomplete scans.
```

Outputs are `inventory.json` (raw evidence), `review.json` and `inventory.csv`. The CSV opens in Excel and includes editable reviewer/decision/ticket/evidence columns. Use Excel's **Data → From Text/CSV** and import identifiers/versions as text. Save as `.xlsx` if desired. No cell is executable and no decision triggers a patch.

For the styled XLSX export, the provided `export_excel.mjs` uses the `@oai/artifact-tool` runtime bundled with Codex. It is an optional presentation step, not an AWS dependency or a claim that this package is publicly installable. On a workstation where that runtime is available, link its provided node_modules into this directory, then run its Node binary:

```bash
node export_excel.mjs reports/demo/review.json reports/demo/PHP-review.xlsx
```

Without that runtime, use the portable CSV/Excel route above. Neither export imports approval decisions back into AWS.

## 2. Collect an explicitly selected AWS scope

Prerequisites: Python 3.8+ on managed Linux nodes; SSM Agent online with the existing managed-instance role and required endpoints; Python 3.11+ and boto3 on the operator workstation. Install the locked AWS dependencies with `python3 -m pip install -r requirements.txt`. Authenticate through an existing AWS SSO/profile. The script does not create IAM roles, endpoints, instances or keys.

A trusted publisher first registers the fixed inventory document in each selected region. It exposes no shell/command parameters. Give the inventory operator SendCommand permission only for this document and the allowed instance ARNs, with no document editing privileges:

```bash
mkdir -p reports
python3 prepare_inventory.py --output reports/PHP-Inventory.json
aws ssm create-document --region eu-west-1 --name PHP-Inventory \
  --document-type Command --document-format JSON --content file://reports/PHP-Inventory.json
```

The collector defaults to `PHP-Inventory` version `1`. Select another reviewed numeric version with `--document-version`; it refuses `$LATEST`.

```bash
AWS_PROFILE=staging python3 inventory.py \
  --regions eu-west-1 eu-central-1 --tag Environment=staging \
  --output reports/before
```

The EC2 enumeration includes running, pending, stopping and stopped instances matching the exact tag. Stopped and unmanaged instances stay in the report. Regions outside the supplied list, other accounts and EC2 hosts outside that tag are outside scope. The collector sends one bounded command per running Linux host, sequentially. This is a small-fleet reference implementation, not a high-throughput organization-wide scanner.

The script is read-only with respect to packages/configuration, but SSM records command execution and the collector starts binaries with `-n -v`. Exit 0 means collection completed, **not** that PHP is patched. Exit 2 means coverage is incomplete. No vulnerability status is written into SSM Compliance.

## 3. Review the report and prepare one canary change

Resolve incomplete scans. For each affected host, identify the *serving* runtime and all PHP branches. Check the vendor advisory, package repositories and exact fixed versions. Record the vendor evidence, owner, change ticket, staging test, backup reference, rollback method, maintenance window, restart services and application health checks. An older version with documented vendor backports may need no package change.

Copy `examples/change-plan.template.json` to `reports/change-plan.json`. Replace every placeholder with reviewed values from your **real** inventory and vendor advisory. The sample versions are deliberately not deployable. Include the complete observed PHP package map in `expected_packages`; include the exact package versions to upgrade in `targets`, including necessary matching core/extension packages. Architecture is part of RPM names. Do not use upstream tarball versions as invented distro package versions.

```bash
shasum -a 256 reports/before/inventory.json
# Copy this digest into inventory_sha256 in the plan.
python3 prepare_change.py --inventory reports/before/inventory.json \
  --plan reports/change-plan.json --output reports/PHP-approved-change.json
```

Preparation makes **no AWS calls**. It rejects synthetic/old inventory, missing review evidence, mismatched targets and package drift. Windows, custom source installations and container image upgrades need their own approved deployment process. For Amazon Linux 2023, specify a tested, exact `releasever` from the vendor release notes. The generator refuses `latest`; it does not choose or upgrade your repository release automatically.

## 4. Register, review and execute in SSM

Have the document publisher/security administrator review the generated JSON and deploy it in the plan's account and region. Restrict document creation/update to that publisher. The runbook has **no runtime parameters**: host, package versions, services, execution role and approver are embedded in its version. Record the document hash/version in the change ticket.

```bash
aws ssm create-document --region eu-west-1 --name PHP-CHG-1234 \
  --document-type Automation --document-format JSON \
  --content file://reports/PHP-approved-change.json
aws ssm start-automation-execution --region eu-west-1 \
  --document-name PHP-CHG-1234 --document-version '1'
```

The Automation pauses at `aws:approve`. The designated approver reviews the exact host, package list, window and plan hash in Systems Manager, then approves or denies. Denial/timeout aborts. Approval outside the maintenance window fails before package changes. IAM must prevent the requester from bypassing this through direct Run Command or document updates. See [security and evidence](docs/security-and-evidence.md).

After approval, the host script rechecks OS and the complete PHP package map. APT compares target versions natively and uses `--only-upgrade --no-remove`; DNF/YUM uses exact package identifiers with `upgrade`. Configured repository trust stays in place, with RPM signature checks explicitly enabled. Unavailable target packages fail; the script never downloads PHP from arbitrary URLs. Package managers may change dependencies and run maintainer scripts, including service restarts. Review the transaction in staging; this is not a PHP-only dependency guarantee.

The script verifies requested package versions, restarts only the listed PHP-FPM/Apache services and checks that they are active. It does **not** reboot, roll back automatically, or prove application health. ALB draining and traffic restoration remain change-ticket tasks. On failure, inspect the SSM output and use the reviewed recovery procedure; a failed operation can leave partial changes.

## 5. Verify and retain evidence

Re-run inventory after the change into a new directory. Check the runtime actually serving requests, all workers, application smoke tests and the October 23 follow-up advisory. Do not expose a public `phpinfo()` page. Record before/after evidence, SSM command and Automation execution IDs, approval identity/time, ticket, exact vendor package evidence and health results. Then close the change or record an exception with an owner and expiry.

This supports your organization's patch/change-control evidence process. It is **not a certification of GDPR, ISO 27001, PCI DSS or other compliance**, and it does not represent AWS Patch Manager baseline compliance. For an established Patch Manager estate, keep its baseline Scan/Install process and use this report for PHP-specific evidence; do not assume a compliant baseline proves these two CVEs were remediated.

## Validation

```bash
python3 -m unittest discover -s tests -v
```

26 offline tests cover version boundaries, backport ambiguity, multiple PHP runtimes, missing coverage, stale inventory, approval ordering, fixed inventory documents, exact package targeting, drift, expired windows and failed-update restart prevention. SSM and package operations are mocked. No live AWS execution or real APT/DNF/YUM transaction has been validated. Test one disposable host per OS/repository combination before operational use.

References: [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5), [AWS PHP bulletin](https://aws.amazon.com/security/security-bulletins/2026-143-aws/), [SSM approval action](https://docs.aws.amazon.com/systems-manager/latest/userguide/automation-action-approve.html), [Patch Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/patch-manager.html), [AL2023 repository versioning](https://docs.aws.amazon.com/linux/al2023/ug/managing-repos-os-updates.html). The supplied CISA link returned HTTP 403 during research; thresholds were checked against the primary PHP advisory.
