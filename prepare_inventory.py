"""Generate a publisher-owned, parameter-free read-only SSM Command document."""
import argparse
import json
from pathlib import Path
from inventory import shell_payload


def document():
    source = Path(__file__).with_name('collector.py').read_text()
    return {'schemaVersion': '2.2', 'description': 'Read-only PHP package and known-path inventory',
            'parameters': {}, 'mainSteps': [{'action': 'aws:runShellScript', 'name': 'InventoryPHP',
            'precondition': {'StringEquals': ['platformType', 'Linux']},
            'inputs': {'timeoutSeconds': '180', 'runCommand': [shell_payload(source)]}}]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    Path(args.output).write_text(json.dumps(document(), indent=2) + '\n')
