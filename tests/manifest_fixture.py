"""Build historical migration fixtures from a current installation manifest."""

import argparse
import json
from pathlib import Path


def historical_manifest(manifest, schema):
    # Round-trip to avoid changing the caller's current-schema fixture.
    result = json.loads(json.dumps(manifest))
    result['schemaVersion'] = schema
    if schema == 1:
        result.pop('gitPolicy', None)
        result.pop('files', None)
    else:
        result['gitPolicy'] = {
            'pushMode': 'manual', 'pushActor': 'ai',
            'mergeMode': 'manual', 'mergeActor': 'ai',
        }
        if schema == 2:
            result['workflowVersion'] = '0.1.9'
            entry = next(item for item in result['files'] if item['path'] == 'docs/TASKS.md')
            entry['installedSha256'] = '0' * 64
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('schema', type=int, choices=(1, 2, 3))
    args = parser.parse_args()
    fixture = historical_manifest(json.loads(args.manifest.read_text(encoding='utf-8')), args.schema)
    serialized = json.dumps(fixture, ensure_ascii=False, indent=2) + '\n'
    # Validate before replacing the installed manifest used by integration tests.
    json.loads(serialized)
    args.manifest.write_text(serialized, encoding='utf-8')


if __name__ == '__main__':
    main()
