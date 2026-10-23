"""Run only inside the approved SSM Automation. Plan is embedded by prepare_change.py."""
import json
import re
import subprocess
from datetime import datetime, timezone


def execute_patch(plan, collect, run=subprocess.run):
    now = datetime.now(timezone.utc)
    start = datetime.fromisoformat(plan['window_start'])
    end = datetime.fromisoformat(plan['window_end'])
    if not start <= now < end:
        raise ValueError('Outside approved maintenance window')
    before = collect()
    if before['errors'] or (before['os_id'], before['os_version'], before['manager']) != (plan['os_id'], plan['os_version'], plan['manager']):
        raise ValueError('Host inventory or OS changed; review again')
    installed = {p['name']: p['version'] for p in before['packages']}
    if installed != plan['expected_packages']:
        raise ValueError('PHP package set drifted since review')
    targets = plan['targets']
    def checked(args, timeout=1200):
        return run(args, check=True, timeout=timeout, text=True)
    for item in targets:
        old, new = installed[item['name']], item['version']
        if old == new:
            continue
        if plan['manager'] == 'apt':
            checked(['dpkg', '--compare-versions', new, 'gt', old], 15)
        # dnf/yum 'upgrade' never intentionally requests a downgrade; verify exact result below.
    if plan['manager'] == 'apt':
        checked(['apt-get', '-o', 'APT::Update::Error-Mode=any', 'update'])
        command = ['apt-get', '-y', '--only-upgrade', '--no-remove', 'install']
        command += [p['name'] + '=' + p['version'] for p in targets]
    else:
        command = [plan['manager'], '-y', '--setopt=gpgcheck=1', '--setopt=skip_if_unavailable=False']
        if plan.get('releasever'):
            command += ['--releasever=' + plan['releasever']]
        command += ['upgrade']
        for item in targets:
            name, arch = item['name'].rsplit('.', 1)
            command += [name + '-' + item['version'] + '.' + arch]
    checked(command)
    after = collect()
    actual = {p['name']: p['version'] for p in after['packages']}
    if after['errors'] or any(actual.get(p['name']) != p['version'] for p in targets):
        raise ValueError('Target package verification failed; do not close the change')
    for service in plan['restart_services']:
        checked(['systemctl', 'restart', service], 120)
        checked(['systemctl', 'is-active', '--quiet', service], 30)
    print(json.dumps({'result': 'PACKAGES_VERIFIED_APPLICATION_REVIEW_REQUIRED',
                      'ticket': plan['ticket'], 'inventory': after,
                      'note': 'Verify served runtime, all worker restarts and application smoke tests separately.'}))
