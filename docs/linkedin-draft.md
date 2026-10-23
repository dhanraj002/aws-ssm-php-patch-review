# LinkedIn draft

The recent PHP security advisory raised a familiar operations question: which servers have PHP installed, and what evidence do we have that the fix is present?

I put together a small AWS Systems Manager workflow for mixed Linux EC2 environments:

• Collect PHP package and binary versions through SSM, without SSH.
• Export the inventory for Excel review, including hosts that could not be scanned.
• Flag vendor backports for review instead of assuming an older version is unpatched.
• Prepare a separate change for one host, with exact package versions and an SSM approval step.
• Recheck package state, restart the listed services, and retain evidence for application validation.

One detail matters: a fixed PHP version on disk is not enough to close the change. The workers serving traffic, application health and any follow-up advisories also need checking.

I validated the workflow on two disposable EC2 instances: Ubuntu 24.04 and Amazon Linux 2023. Both started without PHP, then received older official packages for the upgrade test. A rejected SSM execution stopped before patching. The approved runs upgraded to the reviewed vendor package versions, restarted PHP-FPM and passed a local FastCGI smoke test. I then removed the lab resources.

The Ubuntu result was a useful reminder: its fixed package still reports PHP 8.3.6. The full vendor package revision and advisory are the evidence that matters. This was a personal sandbox test, not a production remediation or compliance certification.

Code: https://github.com/dhanraj002/aws-ssm-php-patch-review
PHP advisory: https://www.php.net/archive/2026.php#2026-10-21-5

How do you handle vendor-backported fixes in your patch review process?

#AWS #SystemsManager #DevOps #VulnerabilityManagement #PHP

---

Publication note: Draft only; not posted to LinkedIn. Use the sanitized live-lab report screenshot, labelled as a rendered AWS API evidence report. Recheck the linked advisories immediately before posting. Avoid claims of production remediation, zero downtime or certified compliance without supporting evidence.
