"""Bounded, read-only host inventory. Executed by SSM with Python 3.8+."""
import glob
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone


def run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=20, check=True).stdout


def collect():
    result = {"schema": 1, "observed_at": datetime.now(timezone.utc).isoformat(),
              "os_id": "unknown", "os_version": "unknown", "manager": "unknown",
              "packages": [], "binaries": [], "errors": [], "coverage": "host-packages-and-known-paths"}
    try:
        with open('/etc/os-release') as stream:
            values = dict(line.strip().split('=', 1) for line in stream if '=' in line)
        result.update(os_id=values.get('ID', '').strip('"'), os_version=values.get('VERSION_ID', '').strip('"'))
    except (OSError, ValueError):
        result['errors'].append('os-release-unavailable')
    try:
        if shutil.which('dpkg-query'):
            result['manager'] = 'apt'
            output = run(['dpkg-query', '-W', '-f=${db:Status-Abbrev}\t${binary:Package}\t${Version}\n'])
            for line in output.splitlines():
                state, name, version = line.split('\t')
                if state.startswith('ii') and 'php' in name.lower():
                    result['packages'].append({'name': name, 'version': version})
        elif shutil.which('rpm'):
            result['manager'] = 'dnf' if shutil.which('dnf') else 'yum' if shutil.which('yum') else 'unknown'
            output = run(['rpm', '-qa', '--qf', '%{NAME}.%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n'])
            for line in output.splitlines():
                name, version = line.split('\t')
                if 'php' in name.lower():
                    result['packages'].append({'name': name, 'version': version})
        else:
            result['errors'].append('unsupported-package-database')
    except (OSError, ValueError, subprocess.SubprocessError):
        result['errors'].append('package-query-failed')
    paths = set()
    for pattern in ['/usr/bin/php*', '/usr/sbin/php*', '/usr/local/bin/php*',
                    '/usr/local/sbin/php*', '/opt/remi/php*/root/usr/bin/php',
                    '/opt/remi/php*/root/usr/sbin/php-fpm']:
        paths.update(glob.glob(pattern))
    for path in sorted(paths):
        if not re.fullmatch(r'php(?:-fpm|-cgi)?(?:\d+(?:\.\d+)*)?', os.path.basename(path)):
            continue
        if not os.path.isfile(path) or not os.access(path, os.X_OK):
            continue
        try:
            output = run([path, '-n', '-v'])
            match = re.search(r'PHP (\d+\.\d+\.\d+[^\s]*)', output)
            result['binaries'].append({'path': path, 'version': match.group(1) if match else 'unknown'})
            if not match:
                result['errors'].append('binary-version-unparsed:' + path)
        except (OSError, subprocess.SubprocessError):
            result['errors'].append('binary-query-failed:' + path)
    result['packages'].sort(key=lambda item: item['name'])
    return result


if __name__ == '__main__':
    payload = json.dumps(collect(), separators=(',', ':'))
    # GetCommandInvocation returns only 24,000 output characters. Never silently truncate.
    if len(payload.encode()) > 22000:
        payload = json.dumps({'schema': 1, 'errors': ['inventory-too-large'], 'packages': [], 'binaries': []})
    print(payload)
