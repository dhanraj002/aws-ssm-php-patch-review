"""Generate a fixed-target, approval-gated SSM Automation document; makes no AWS calls."""
import argparse
import base64
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import re
from inventory import shell_payload


def timestamp(value):
    result = datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise ValueError('Use timezone-aware timestamps')
    return result


def validate(plan, report, now=None):
    now = now or datetime.now(timezone.utc)
    if report['source'] != 'AWS' or report.get('coverage_errors'):
        raise ValueError('Real AWS inventory with complete regional enumeration required')
    if not timedelta(0) <= now - timestamp(report['generated_at']) <= timedelta(hours=24):
        raise ValueError('Inventory must be less than 24 hours old')
    if plan['account'] != report['account'] or not re.fullmatch(r'\d{12}', plan['account']):
        raise ValueError('Account mismatch')
    hosts = [h for h in report['hosts'] if (h['region'], h['instance_id']) == (plan['region'], plan['instance_id'])]
    if len(hosts) != 1 or hosts[0]['scan_status'] != 'SUCCESS':
        raise ValueError('Exactly one successfully scanned target required')
    inv = hosts[0]['inventory']
    if inv['errors'] or not inv['packages']:
        raise ValueError('Complete package inventory required')
    for field in ('os_id', 'os_version', 'manager'):
        if plan[field] != inv[field]:
            raise ValueError('OS/manager mismatch')
    if plan['manager'] not in ('apt', 'dnf', 'yum'):
        raise ValueError('Unsupported manager')
    if not re.fullmatch(r'i-[a-f0-9]{8}(?:[a-f0-9]{9})?', plan['instance_id']):
        raise ValueError('Invalid instance ID')
    if not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d', plan['region']):
        raise ValueError('Invalid region')
    start, end = timestamp(plan['window_start']), timestamp(plan['window_end'])
    if not now < end or not timedelta(0) < end - start <= timedelta(hours=4) or end > now + timedelta(hours=24):
        raise ValueError('Window must end within 24 hours and last at most four hours')
    for key in ('ticket', 'reviewer', 'backup_reference', 'rollback_plan', 'health_check_plan', 'vendor_evidence'):
        if not isinstance(plan.get(key), str) or not plan[key].strip() or len(plan[key]) > 500 or '{{' in plan[key]:
            raise ValueError('Missing or invalid review evidence: ' + key)
    if not plan['vendor_evidence'].startswith('https://'):
        raise ValueError('Provide the vendor advisory URL for BOTH CVEs and the exact OS release')
    expected = {p['name']: p['version'] for p in inv['packages']}
    if plan['expected_packages'] != expected:
        raise ValueError('Plan must retain the complete observed PHP package set')
    targets = plan['targets']
    if not 1 <= len(targets) <= 30 or len({p['name'] for p in targets}) != len(targets):
        raise ValueError('One to thirty unique package targets required')
    for item in targets:
        if item['name'] not in expected or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.+:_-]*', item['name']):
            raise ValueError('Only observed PHP package names are accepted')
        if not re.fullmatch(r'[0-9][a-zA-Z0-9.+:~_-]*', item['version']):
            raise ValueError('Exact package version required; no wildcards or command text')
        if plan['manager'] != 'apt' and '.' not in item['name']:
            raise ValueError('RPM name must include architecture')
    if not isinstance(plan['restart_services'], list) or not 1 <= len(plan['restart_services']) <= 10:
        raise ValueError('Review and list the serving services to restart')
    for service in plan['restart_services']:
        if not re.fullmatch(r'(?:php[0-9.-]*fpm|php[0-9.-]*-php-fpm|apache2|httpd)\.service', service):
            raise ValueError('Service is outside the supported PHP/FPM/Apache allowlist')
    if plan.get('releasever') and not re.fullmatch(r'2023\.\d+\.\d{8}', plan['releasever']):
        raise ValueError('Use an exact AL2023 repository release, never latest')
    if plan['os_id'] == 'amzn' and plan['os_version'] == '2023' and not plan.get('releasever'):
        raise ValueError('AL2023 requires a reviewed, exact releasever')
    for key, role_kind in [('automation_role', 'role'), ('approver_arn', '(?:role|user)')]:
        if not re.fullmatch(r'arn:aws:iam::' + plan['account'] + ':' + role_kind + r'/[\w+=,.@/-]+', plan[key]):
            raise ValueError('Use an IAM ARN in the target account')
    if plan['automation_role'] == plan['approver_arn']:
        raise ValueError('Execution role must not be the approver')


def document(plan):
    here = Path(__file__).parent
    raw = json.dumps(plan, sort_keys=True, separators=(',', ':'))
    digest = hashlib.sha256(raw.encode()).hexdigest()
    encoded = base64.b64encode(raw.encode()).decode()
    script = (here / 'collector.py').read_text().split("if __name__ == '__main__':")[0]
    script += '\n' + (here / 'patch_host.py').read_text()
    script += "\nimport base64\nexecute_patch(json.loads(base64.b64decode('" + encoded + "')), collect)\n"
    message = ('Review change ' + plan['ticket'] + '\nHost: ' + plan['account'] + '/' + plan['region'] + '/' + plan['instance_id']
               + '\nWindow: ' + plan['window_start'] + ' to ' + plan['window_end']
               + '\nPackages: ' + json.dumps(plan['targets']) + '\nRestart: ' + ', '.join(plan['restart_services'])
               + '\nVendor: ' + plan['vendor_evidence'] + '\nPlan SHA256: ' + digest
               + '\nDependencies may change and package scripts may restart services. Confirm backup, staging test and rollback in the ticket.')
    if len(message) > 4096:
        raise ValueError('Approval message too long; use a smaller reviewed change')
    return {'schemaVersion': '0.3', 'description': 'PHP package remediation: ' + plan['ticket'] + '; plan SHA256 ' + digest,
            'assumeRole': plan['automation_role'], 'parameters': {}, 'mainSteps': [
                {'name': 'ApproveReviewedChange', 'action': 'aws:approve', 'timeoutSeconds': 86400,
                 'onFailure': 'Abort', 'inputs': {'Approvers': [plan['approver_arn']], 'MinRequiredApprovals': 1, 'Message': message}},
                {'name': 'PatchAndVerifyPackages', 'action': 'aws:runCommand', 'timeoutSeconds': 2400,
                 'onFailure': 'Abort', 'isEnd': True, 'inputs': {'DocumentName': 'AWS-RunShellScript',
                 'InstanceIds': [plan['instance_id']], 'Parameters': {'commands': [shell_payload(script)], 'executionTimeout': ['2200']},
                 'Comment': plan['ticket'][:100]}}]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', required=True)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    payload = Path(args.inventory).read_bytes()
    plan = json.loads(Path(args.plan).read_text())
    if plan['inventory_sha256'] != hashlib.sha256(payload).hexdigest():
        raise ValueError('Inventory hash mismatch')
    validate(plan, json.loads(payload))
    output = Path(args.output)
    output.write_text(json.dumps(document(plan), indent=2) + '\n')
    output.chmod(0o600)
    print('Prepared only; no AWS calls. Review and register a pinned document version in ' + plan['region'])


if __name__ == '__main__':
    main()
