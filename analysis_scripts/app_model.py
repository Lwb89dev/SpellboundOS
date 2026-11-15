#!/usr/bin/env python3
"""Map the app-loading contract the packaged apps rely on.

Above the native ABI (see js_runtime_api.py), the readable
``META/js_watchfaces/*/*.js`` bundles reveal the host contract: the
native-injected ``__$$name$$__`` globals, the ``DeviceRuntimeCore.*`` entry
points the apps construct, and the app lifecycle hooks they define.

These are static observations of shipped JavaScript, not executed. A standalone
OS that runs these apps would have to provide the injected globals, expose a
``DeviceRuntimeCore`` with these entry points, and drive these lifecycle hooks.
The ``framework.js`` runtime's full export list is not enumerated here because
its minified source reuses the exports identifier as an ordinary parameter,
which makes a reliable static count impossible; only the entry points the apps
actually use are reported.
"""
import argparse
import hashlib
import json
import re
import zipfile

FRAMEWORK = 'META/js_apps/framework.js'
LIFECYCLE_RE = re.compile(r'\b(on[A-Z][A-Za-z]+)\s*[(:]')


def injected_globals(text):
    return sorted(set(re.findall(r'__\$\$([A-Za-z]\w*)\$\$__', text)))


def runtime_entry_points(text):
    return sorted(set(re.findall(r'DeviceRuntimeCore\.([A-Za-z_]\w*)', text)))


def lifecycle_hooks(text):
    return sorted(set(LIFECYCLE_RE.findall(text)))


def inspect(archive):
    members = sorted(n for n in archive.namelist()
                     if n.startswith('META/js_watchfaces/') and n.endswith('.js'))
    bundle_text = '\n'.join(archive.read(n).decode('utf-8', 'replace')
                            for n in members)
    return {
        'injected_host_globals': injected_globals(bundle_text),
        'runtime_entry_points_used': runtime_entry_points(bundle_text),
        'lifecycle_hooks': lifecycle_hooks(bundle_text),
        'bundle_members': members,
        'framework_sha256': hashlib.sha256(
            archive.read(FRAMEWORK)).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        result = inspect(archive)
    print(json.dumps(result, indent=2, ensure_ascii=True, sort_keys=True))


if __name__ == '__main__':
    main()
