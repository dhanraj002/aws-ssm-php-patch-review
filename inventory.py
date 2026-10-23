"""Explicitly scoped SSM inventory. No package/configuration changes."""
import argparse
import base64
import csv
import json
import os
from pathlib import Path
import time
from datetime import datetime, timezone
from assess import rows


def shell_payload(source):
    encoded = base64.b64encode(source.encode()).decode()
    return "python3 -c \"import base64;exec(compile(base64.b64decode('" + encoded + "'),'<ssm>','exec'))\""


def wait_result(ssm, command, instance, timeout=240):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            reply = ssm.get_command_invocation(CommandId=command, InstanceId=instance)
            if reply['Status'] not in ('Pending', 'InProgress', 'Delayed', 'Cancelling'):
                return reply
        except ssm.exceptions.InvocationDoesNotExist:
            pass  # Run Command is eventually consistent.
        time.sleep(2)
    return {'Status': 'PollingTimeout'}


def scan(session, regions, tag, document_name='PHP-Inventory', document_version='1'):
    report = {'schema': 1, 'source': 'AWS', 'account': session.client('sts').get_caller_identity()['Account'],
              'generated_at': datetime.now(timezone.utc).isoformat(), 'scope_tag': tag,
              'regions': regions, 'coverage_errors': [], 'hosts': []}
    key, value = tag.split('=', 1)
    for region in regions:
        ec2 = session.client('ec2', region_name=region)
        ssm = session.client('ssm', region_name=region)
        try:
            pages = ec2.get_paginator('describe_instances').paginate(Filters=[
                {'Name': 'tag:' + key, 'Values': [value]},
                {'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']}])
            for page in pages:
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        host = {'region': region, 'instance_id': instance['InstanceId'], 'scan_status': 'NOT_SCANNED'}
                        report['hosts'].append(host)
                        if instance['State']['Name'] != 'running':
                            host['scan_status'] = 'NOT_RUNNING'
                            continue
                        if instance.get('Platform') == 'windows':
                            host['scan_status'] = 'UNSUPPORTED_WINDOWS'
                            continue
                        try:
                            command = ssm.send_command(InstanceIds=[instance['InstanceId']],
                                DocumentName=document_name, DocumentVersion=document_version, Parameters={},
                                TimeoutSeconds=60, Comment='Read-only PHP inventory')['Command']['CommandId']
                            host['command_id'] = command
                            reply = wait_result(ssm, command, instance['InstanceId'])
                            host['scan_status'] = reply['Status']
                            if reply['Status'] == 'Success':
                                inv = json.loads(reply['StandardOutputContent'])
                                if inv.get('schema') != 1 or not isinstance(inv.get('packages'), list) or not isinstance(inv.get('binaries'), list):
                                    raise ValueError('Invalid collector schema')
                                host.update(scan_status='SUCCESS', inventory=inv)
                        except Exception as error:
                            # No raw service exceptions: they can contain private request data.
                            host['scan_status'] = 'ERROR_' + type(error).__name__
        except Exception as error:
            report['coverage_errors'].append({'region': region, 'error': type(error).__name__})
    return report


def save(report, output):
    directory = Path(output)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name in ('inventory.json', 'review.json', 'inventory.csv'):
        if (directory / name).is_symlink():
            raise ValueError('Refusing symlink output')
    review = rows(report)
    (directory / 'inventory.json').write_text(json.dumps(report, indent=2) + '\n')
    (directory / 'review.json').write_text(json.dumps({'report': report, 'rows': review}, indent=2) + '\n')
    fields = list(review[0]) if review else ['account', 'region', 'instance_id', 'assessment']
    with (directory / 'inventory.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows({key: ("'" + val if isinstance(val, str) and val.lstrip().startswith(('=', '+', '-', '@')) else val)
                         for key, val in row.items()} for row in review)
    for name in ('inventory.json', 'review.json', 'inventory.csv'):
        os.chmod(directory / name, 0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture')
    parser.add_argument('--regions', nargs='+')
    parser.add_argument('--tag', help='Explicit EC2 scope, e.g. Environment=staging')
    parser.add_argument('--output', required=True)
    parser.add_argument('--document-name', default='PHP-Inventory')
    parser.add_argument('--document-version', default='1', help='Published numeric version, never $LATEST')
    args = parser.parse_args()
    if args.fixture:
        report = json.loads(Path(args.fixture).read_text())
    else:
        if not args.regions or not args.tag or '=' not in args.tag or not all(args.tag.split('=', 1)):
            parser.error('--regions and a nonempty --tag Key=Value are required for AWS')
        import boto3
        if not args.document_version.isdigit() or int(args.document_version) < 1:
            parser.error('Use a positive numeric document version')
        report = scan(boto3.Session(), args.regions, args.tag, args.document_name, args.document_version)
    save(report, args.output)
    incomplete = bool(report['coverage_errors']) or any(row['assessment'] == 'SCAN_INCOMPLETE' for row in rows(report))
    print(f"{len(report['hosts'])} hosts; coverage incomplete={incomplete}; {args.output}")
    return 2 if incomplete else 0


if __name__ == '__main__':
    raise SystemExit(main())
