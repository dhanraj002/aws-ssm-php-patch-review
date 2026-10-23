import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from assess import assess, version_state
from collector import collect
from inventory import save, scan, wait_result
from patch_host import execute_patch
from prepare_change import document, validate
from prepare_inventory import document as inventory_document

NOW = datetime.now(timezone.utc)


def fixtures():
    inv = {'schema': 1, 'errors': [], 'os_id': 'ubuntu', 'os_version': '24.04', 'manager': 'apt',
           'packages': [{'name': 'php8.3-fpm', 'version': '8.3.6-0ubuntu0.24.04.1'}], 'binaries': []}
    host = {'region': 'eu-west-1', 'instance_id': 'i-0123456789abcdef0', 'scan_status': 'SUCCESS', 'inventory': inv}
    report = {'source': 'AWS', 'account': '123456789012', 'generated_at': NOW.isoformat(), 'coverage_errors': [], 'hosts': [host]}
    plan = {'account': report['account'], 'region': host['region'], 'instance_id': host['instance_id'],
            'os_id': 'ubuntu', 'os_version': '24.04', 'manager': 'apt',
            'window_start': (NOW - timedelta(minutes=1)).isoformat(), 'window_end': (NOW + timedelta(hours=1)).isoformat(),
            'ticket': 'CHG-TEST', 'reviewer': 'Test reviewer', 'backup_reference': 'test backup',
            'rollback_plan': 'restore tested image', 'health_check_plan': 'application smoke tests',
            'vendor_evidence': 'https://example.invalid/TEST-NOT-A-VENDOR-ADVISORY',
            'expected_packages': {'php8.3-fpm': '8.3.6-0ubuntu0.24.04.1'},
            'targets': [{'name': 'php8.3-fpm', 'version': '8.3.36-1'}],
            'restart_services': ['php8.3-fpm.service'], 'automation_role': 'arn:aws:iam::123456789012:role/PatchExecution',
            'approver_arn': 'arn:aws:iam::123456789012:role/ChangeApprover'}
    return report, plan


class AssessmentTests(unittest.TestCase):
    def test_fixed_boundaries_all_branches(self):
        for fixed, old in [('8.2.35', '8.2.34'), ('8.3.36', '8.3.35'), ('8.4.27', '8.4.26'), ('8.5.12', '8.5.11')]:
            self.assertEqual(version_state(fixed), 'UPSTREAM_FIX_LEVEL')
            self.assertEqual(version_state(old), 'VENDOR_FIX_REVIEW')

    def test_distro_epoch_and_backport(self):
        self.assertEqual(version_state('2:8.3.36-0ubuntu1'), 'UPSTREAM_FIX_LEVEL')
        self.assertEqual(version_state('8.3.6-0ubuntu999'), 'VENDOR_FIX_REVIEW')

    def test_prerelease_unknown_and_eol(self):
        for version in ['8.5.12RC1', '8.5.12~rc1', '8.5.12-dev', 'garbage']:
            self.assertEqual(version_state(version), 'VERSION_REVIEW')
        self.assertEqual(version_state('8.1.99'), 'UNSUPPORTED_BRANCH_REVIEW')
        self.assertEqual(version_state('8.6.0'), 'UNSUPPORTED_BRANCH_REVIEW')

    def test_failed_host_not_absent(self):
        self.assertEqual(assess({'scan_status': 'AccessDenied'})[0], 'SCAN_INCOMPLETE')

    def test_empty_host_bounded_absence(self):
        report, _ = fixtures()
        host = report['hosts'][0]
        host['inventory']['packages'] = []
        self.assertEqual(assess(host)[0], 'NOT_DETECTED_IN_SCOPE')

    def test_multiple_runtimes_old_wins(self):
        report, _ = fixtures()
        host = report['hosts'][0]
        host['inventory']['binaries'] = [{'path': '/usr/bin/php', 'version': '8.5.12'}]
        self.assertEqual(assess(host)[0], 'VENDOR_FIX_REVIEW')

    def test_extensions_cannot_assert_core_fix(self):
        report, _ = fixtures()
        host = report['hosts'][0]
        host['inventory']['packages'] = [{'name': 'php-redis', 'version': '8.5.12'}]
        self.assertEqual(assess(host)[0], 'VERSION_REVIEW')


class GateTests(unittest.TestCase):
    def test_valid_document_has_approval_before_mutation(self):
        report, plan = fixtures()
        validate(plan, report, NOW)
        doc = document(plan)
        self.assertEqual(doc['parameters'], {})
        self.assertEqual([s['action'] for s in doc['mainSteps']], ['aws:approve', 'aws:runCommand'])
        self.assertEqual(doc['mainSteps'][0]['onFailure'], 'Abort')
        self.assertEqual(doc['mainSteps'][1]['inputs']['InstanceIds'], [plan['instance_id']])
        self.assertIn('8.3.36-1', doc['mainSteps'][0]['inputs']['Message'])
        self.assertLess(len(json.dumps(doc).encode()), 64000)

    def test_no_fixture_or_incomplete_coverage(self):
        for field, value in [('source', 'SYNTHETIC'), ('coverage_errors', ['AccessDenied'])]:
            report, plan = fixtures()
            report[field] = value
            with self.assertRaises(ValueError): validate(plan, report, NOW)

    def test_stale_inventory(self):
        report, plan = fixtures()
        report['generated_at'] = (NOW - timedelta(days=2)).isoformat()
        with self.assertRaises(ValueError): validate(plan, report, NOW)

    def test_unknown_target_account_and_drift(self):
        for key, value in [('instance_id', 'i-11111111111111111'), ('account', '111111111111'), ('expected_packages', {})]:
            report, plan = fixtures()
            plan[key] = value
            with self.assertRaises(ValueError): validate(plan, report, NOW)

    def test_missing_review_fields(self):
        for field in ['ticket', 'reviewer', 'backup_reference', 'rollback_plan', 'health_check_plan', 'vendor_evidence']:
            report, plan = fixtures()
            plan[field] = ''
            with self.assertRaises(ValueError): validate(plan, report, NOW)

    def test_no_shell_wildcards_new_package_or_service(self):
        for version in ['8.*', '8.3.36;id', '--latest', '8.3.36$(id)']:
            report, plan = fixtures()
            plan['targets'][0]['version'] = version
            with self.assertRaises(ValueError): validate(plan, report, NOW)
        report, plan = fixtures()
        plan['restart_services'] = ['sshd.service']
        with self.assertRaises(ValueError): validate(plan, report, NOW)

    def test_no_execution_role_approval(self):
        report, plan = fixtures()
        plan['approver_arn'] = plan['automation_role']
        with self.assertRaises(ValueError): validate(plan, report, NOW)

    def test_al2023_requires_exact_release(self):
        report, plan = fixtures()
        for obj in [report['hosts'][0]['inventory'], plan]:
            obj.update(os_id='amzn', os_version='2023', manager='dnf')
        plan['targets'] = [{'name': 'php8.3-fpm.x86_64', 'version': '0:8.3.36-1.amzn2023'}]
        report['hosts'][0]['inventory']['packages'] = [{'name': 'php8.3-fpm.x86_64', 'version': '0:8.3.35-1.amzn2023'}]
        plan['expected_packages'] = {'php8.3-fpm.x86_64': '0:8.3.35-1.amzn2023'}
        with self.assertRaises(ValueError): validate(plan, report, NOW)
        plan['releasever'] = 'latest'
        with self.assertRaises(ValueError): validate(plan, report, NOW)
        plan['releasever'] = '2023.12.20261022'
        validate(plan, report, NOW)


class ExecutionTests(unittest.TestCase):
    def test_drift_aborts_without_any_command(self):
        report, plan = fixtures()
        inv = copy.deepcopy(report['hosts'][0]['inventory'])
        inv['packages'][0]['version'] = 'different'
        runner = Mock()
        with self.assertRaises(ValueError): execute_patch(plan, lambda: inv, runner)
        runner.assert_not_called()

    def test_expired_window_aborts(self):
        report, plan = fixtures()
        plan['window_end'] = (NOW - timedelta(seconds=1)).isoformat()
        collector, runner = Mock(), Mock()
        with self.assertRaises(ValueError): execute_patch(plan, collector, runner)
        collector.assert_not_called()
        runner.assert_not_called()

    def test_exact_versions_verified_before_restart(self):
        report, plan = fixtures()
        before = report['hosts'][0]['inventory']
        after = copy.deepcopy(before)
        after['packages'] = plan['targets']
        runner = Mock()
        execute_patch(plan, Mock(side_effect=[before, after]), runner)
        commands = [call.args[0] for call in runner.call_args_list]
        self.assertIn(['apt-get', '-y', '--only-upgrade', '--no-remove', 'install', 'php8.3-fpm=8.3.36-1'], commands)
        self.assertEqual(commands[-1], ['systemctl', 'is-active', '--quiet', 'php8.3-fpm.service'])

    def test_failed_patch_never_restarts(self):
        report, plan = fixtures()
        runner = Mock(side_effect=subprocess.CalledProcessError(1, 'apt-get'))
        with self.assertRaises(subprocess.CalledProcessError): execute_patch(plan, lambda: report['hosts'][0]['inventory'], runner)
        self.assertFalse(any('systemctl' in call.args[0] for call in runner.call_args_list))

    def test_wrong_result_never_restarts(self):
        report, plan = fixtures()
        runner = Mock()
        with self.assertRaises(ValueError): execute_patch(plan, lambda: report['hosts'][0]['inventory'], runner)
        self.assertFalse(any('systemctl' in call.args[0] for call in runner.call_args_list))

    def test_rpm_exact_epoch_version_architecture(self):
        report, plan = fixtures()
        plan.update(manager='dnf', os_id='amzn', os_version='2023', releasever='2023.12.20261022')
        plan['expected_packages'] = {'php8.3-fpm.x86_64': '0:8.3.35-1.amzn2023'}
        plan['targets'] = [{'name': 'php8.3-fpm.x86_64', 'version': '0:8.3.36-1.amzn2023'}]
        before = dict(report['hosts'][0]['inventory'], manager='dnf', os_id='amzn', os_version='2023',
                      packages=[{'name': k, 'version': v} for k, v in plan['expected_packages'].items()])
        after = dict(before, packages=plan['targets'])
        runner = Mock()
        execute_patch(plan, Mock(side_effect=[before, after]), runner)
        self.assertIn('php8.3-fpm-0:8.3.36-1.amzn2023.x86_64', runner.call_args_list[0].args[0])


class InventoryTests(unittest.TestCase):
    def test_fixed_inventory_document_cannot_accept_commands(self):
        doc = inventory_document()
        self.assertEqual(doc['parameters'], {})
        self.assertEqual(doc['mainSteps'][0]['precondition'], {'StringEquals': ['platformType', 'Linux']})
        self.assertNotIn('{{', json.dumps(doc))

    def test_csv_formula_injection(self):
        report, _ = fixtures()
        report['hosts'][0]['inventory']['packages'][0]['name'] = '=HYPERLINK("evil")'
        with tempfile.TemporaryDirectory() as temp:
            save(report, temp)
            text = (Path(temp) / 'inventory.csv').read_text()
            self.assertIn("'=HYPERLINK", text)

    def test_collector_package_failure_is_incomplete(self):
        with patch('collector.shutil.which', return_value='/usr/bin/dpkg-query'), patch('collector.glob.glob', return_value=[]), patch('collector.run', side_effect=OSError()):
            result = collect()
        self.assertIn('package-query-failed', result['errors'])

    def test_stopped_and_unmanaged_nodes_remain_visible(self):
        session = Mock()
        sts, ec2, ssm = Mock(), Mock(), Mock()
        session.client.side_effect = lambda name, **kw: {'sts': sts, 'ec2': ec2, 'ssm': ssm}[name]
        sts.get_caller_identity.return_value = {'Account': '123456789012'}
        ec2.get_paginator.return_value.paginate.return_value = [{'Reservations': [{'Instances': [
            {'InstanceId': 'i-00000000000000001', 'State': {'Name': 'stopped'}},
            {'InstanceId': 'i-00000000000000002', 'State': {'Name': 'running'}}]}]}]
        ssm.send_command.side_effect = RuntimeError('not managed')
        report = scan(session, ['eu-west-1'], 'Environment=staging')
        self.assertEqual(len(report['hosts']), 2)
        self.assertEqual(report['hosts'][0]['scan_status'], 'NOT_RUNNING')
        self.assertEqual(report['hosts'][1]['scan_status'], 'ERROR_RuntimeError')

    def test_region_failure_not_clean_empty_report(self):
        session = Mock()
        session.client.return_value.get_caller_identity.return_value = {'Account': '123456789012'}
        session.client.return_value.get_paginator.return_value.paginate.side_effect = RuntimeError()
        report = scan(session, ['eu-west-1'], 'Environment=staging')
        self.assertEqual(len(report['coverage_errors']), 1)


if __name__ == '__main__':
    unittest.main()
