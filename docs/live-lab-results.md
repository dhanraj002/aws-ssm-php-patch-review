# Live lab validation — 23 October 2026

Two disposable t3.micro instances in us-east-1 ran Ubuntu 24.04 and Amazon Linux 2023. Each used an encrypted 8 GiB gp3 root volume, IMDSv2, standard CPU credits and no inbound security-group rules. SSM provided access without SSH. Public IPv4 and outbound HTTP/HTTPS avoided a NAT gateway. A scheduled shutdown with terminate-on-shutdown provided a 90-minute backstop.

| Check | Ubuntu 24.04 | Amazon Linux 2023 |
| --- | --- | --- |
| Initial clean-host inventory | PHP not detected in scope | PHP not detected in scope |
| Baseline PHP-FPM package | 8.3.6-0maysync1 | 0:8.3.35-1.amzn2023.0.1 |
| Approved target package | 8.3.6-0ubuntu0.24.04.13 | 0:8.3.36-1.amzn2023.0.1 |
| SSM Automation result | Success | Success |
| FPM restart and FastCGI JSON smoke test | Passed; new PID | Passed; new PID |
| Runtime version after change | 8.3.6 (vendor backport) | 8.3.36 |

The first Ubuntu Automation execution was deliberately rejected. AWS reported its approval step as Failed/Rejected and left the patch step Pending; no patch command ran. Fresh approved executions then upgraded five Ubuntu PHP packages and four Amazon Linux PHP packages. Exact target versions were verified. Amazon Linux used repository release `2023.12.20261021`.

Vendor review covered [Ubuntu USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1) and [Amazon ALAS2023-2026-3302](https://alas.aws.amazon.com/AL2023/ALAS2023-2026-3302.html) for CVE-2026-109618 and CVE-2026-109619. The generic scanner intentionally retains `VENDOR_FIX_REVIEW` for Ubuntu; a PHP binary version alone cannot prove its backported fix.

## Issues found and corrected

- AWS rejected multiline `aws:approve` messages against its `.{1,4096}` schema. The generator now emits one line, with a regression assertion.
- Debian's `php-common` support-package version was incorrectly treated as a PHP engine version. APT assessment now excludes unversioned support/metapackages while RPM engine packages remain assessed. Two regression tests cover this distinction.
- The initial Amazon Linux smoke-test file was under `/var/tmp`, hidden by FPM service isolation. Moving the disposable test file to `/usr/share` let the check run without weakening service isolation.

All 28 offline tests passed. Raw AWS execution, command, inventory and cleanup evidence stays local; public documentation omits account and resource identifiers.

## Cleanup and limits

Both instances were terminated after approximately 13 minutes. Verification at 17:01 UTC found zero lab EBS volumes or network interfaces. Both temporary IAM roles, the instance profile, the security group and all three SSM documents were removed. AWS retains service execution history according to its retention rules.

The same authorized IAM user initiated and approved sandbox runs. This does not prove independent organizational approval controls. The smoke test exercised FPM through a Unix socket, not a production website, database, load balancer or container. No rollback execution, downtime guarantee, formal compliance certification or protection against later advisories is claimed. Production deployment still needs its own staging, backup/restore and application tests.
