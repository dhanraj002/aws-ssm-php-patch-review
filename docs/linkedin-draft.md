# LinkedIn draft

The recent PHP security advisory raised a familiar operations question: which servers have PHP installed, and what evidence do we have that the fix is present?

I put together a small AWS Systems Manager workflow for mixed Linux EC2 environments:

• Collect PHP package and binary versions through SSM, without SSH.
• Export the inventory for Excel review, including hosts that could not be scanned.
• Flag vendor backports for review instead of assuming an older version is unpatched.
• Prepare a separate change for one host, with exact package versions and an SSM approval step.
• Recheck package state, restart the listed services, and retain evidence for application validation.

One detail matters: a fixed PHP version on disk is not enough to close the change. The workers serving traffic, application health and any follow-up advisories also need checking.

This is a reference implementation with offline tests and synthetic inventory. I have not yet validated it against a live AWS fleet. The aim is a repeatable review and change-control process with clear evidence and explicit gaps.

Code: https://github.com/dhanraj002/aws-ssm-php-patch-review
PHP advisory: https://www.php.net/archive/2026.php#2026-10-21-5

How do you handle vendor-backported fixes in your patch review process?

#AWS #SystemsManager #DevOps #VulnerabilityManagement #PHP

---

Publication note: Draft only; not posted to LinkedIn. Keep the live-validation statement until you have actual execution evidence. Use only synthetic screenshots. Recheck the linked advisories immediately before posting. Avoid claims of production remediation, zero downtime or certified compliance without supporting evidence.
