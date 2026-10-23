"""Assessment of the two October 21 CVEs; never asserts host compliance."""
import re

FIXED = {'8.2': (8, 2, 35), '8.3': (8, 3, 36), '8.4': (8, 4, 27), '8.5': (8, 5, 12)}
CVES = ['CVE-2026-109618', 'CVE-2026-109619']
SOURCE = 'https://www.php.net/archive/2026.php#2026-10-21-5'


def version_state(raw):
    # Accept distro epoch/release suffixes, but never prereleases as fixed.
    value = re.sub(r'^\d+:', '', raw)
    match = re.match(r'^(\d+)\.(\d+)\.(\d+)(.*)$', value)
    if not match:
        return 'VERSION_REVIEW'
    version = tuple(int(match[i]) for i in (1, 2, 3))
    suffix = match[4]
    if suffix and not suffix.startswith(('-', '+', '.')):
        return 'VERSION_REVIEW'
    if re.search(r'(?:rc|alpha|beta|dev|~)', suffix, re.I):
        return 'VERSION_REVIEW'
    branch = '.'.join(map(str, version[:2]))
    if branch not in FIXED:
        return 'UNSUPPORTED_BRANCH_REVIEW'
    return 'UPSTREAM_FIX_LEVEL' if version >= FIXED[branch] else 'VENDOR_FIX_REVIEW'


def assess(host):
    inventory = host.get('inventory', {})
    if host.get('scan_status') != 'SUCCESS' or inventory.get('errors'):
        return 'SCAN_INCOMPLETE', 'Unknown', 'Resolve scan errors before assessing PHP.'
    packages, binaries = inventory.get('packages', []), inventory.get('binaries', [])
    if not packages and not binaries:
        return 'NOT_DETECTED_IN_SCOPE', 'Not detected in scope', 'Check containers, custom paths and bundled runtimes separately.'
    states = [version_state(item['version']) for item in binaries]
    # Extension package versions are not necessarily the PHP engine version.
    core = [p for p in packages if re.search(r'(?:^php(?:\d+(?:\.\d+)*)?-(?:common|cli|fpm|cgi)|^libapache2-mod-php|^php(?:\d+(?:\.\d+)*)?(?:\.|:|$)|-php-(?:common|cli|fpm|cgi))', p['name'])]
    states.extend(version_state(item['version']) for item in core)
    if not states:
        return 'VERSION_REVIEW', 'Detected', 'PHP-related packages found; confirm the serving runtime and vendor fix.'
    for state in ('UNSUPPORTED_BRANCH_REVIEW', 'VERSION_REVIEW', 'VENDOR_FIX_REVIEW'):
        if state in states:
            return state, 'Detected', 'Check exact OS/package advisory for BOTH CVEs; older versions may be backported.'
    return 'FIX_LEVEL_DETECTED', 'Detected', 'On-disk fix level only. Verify all web workers, restart and application health.'


def rows(report):
    result = []
    for host in report['hosts']:
        inv = host.get('inventory', {})
        state, installed, action = assess(host)
        result.append({'account': report['account'], 'region': host['region'], 'instance_id': host['instance_id'],
                       'os': inv.get('os_id', 'unknown') + ' ' + inv.get('os_version', ''),
                       'php': installed, 'assessment': state,
                       'versions': '; '.join(p['name'] + '=' + p['version'] for p in inv.get('packages', [])),
                       'binaries': '; '.join(p['path'] + '=' + p['version'] for p in inv.get('binaries', [])),
                       'scan': host['scan_status'], 'command_id': host.get('command_id', ''),
                       'action': action, 'reviewer': '', 'decision': 'Pending', 'ticket': '',
                       'vendor_evidence': '', 'restart_health_evidence': ''})
    return result
