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


def _string_array_containing(text, marker):
    for match in re.finditer(r'\[((?:"[^"\\]*",?)+)\]', text):
        items = re.findall(r'"([^"\\]*)"', match.group(1))
        if marker in items:
            return match, items
    return None, []


def _top_level_keys(literal):
    """Keys of a minified object literal, ignoring nested braces/parens."""
    keys, depth, token = [], 0, ''
    for char in literal[1:-1]:
        if char in '{([':
            depth += 1
        elif char in '})]':
            depth -= 1
        if depth == 0 and char == ',':
            token = ''
            continue
        if depth == 0 and char == ':' and re.fullmatch(r'[\w$]+', token):
            keys.append(token)
            token = '\0'  # do not collect again until the next comma
            continue
        if token != '\0':
            token += char
    return keys


def _literal_at(text, start):
    depth = 0
    for index in range(start, len(text)):
        if text[index] in '{([':
            depth += 1
        elif text[index] in '})]':
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    raise ValueError('unterminated literal')


def sandbox_contract(framework_text):
    """The app ProxySandbox lists and the injected app-scope object keys.

    Located by content in this build: the hidden-name array contains
    ``"__loadScript"`` and is followed by the ``Symbol.unscopables`` object; the
    alias array contains ``"globalThis"``; the app scope object starts with
    ``{__$$R$$__:``.
    """
    result = {}
    match, hidden = _string_array_containing(framework_text, '__loadScript')
    if match:
        result['sandbox_hidden_names'] = hidden
        after = framework_text[match.end():match.end() + 16]
        unscopable = re.match(r',[\w$]+=\{', after)
        if unscopable:
            literal = _literal_at(framework_text, match.end() + unscopable.end() - 1)
            result['unscopables'] = {k: v == '0' for k, v in
                                     re.findall(r'([\w$]+):!([01])', literal)}
    _, aliases = _string_array_containing(framework_text, 'globalThis')
    if aliases:
        result['global_aliases'] = aliases
    # The first '{__$$R$$__:' is a destructuring pattern; the scope object is the
    # literal that also carries __$$app$$__.
    for match in re.finditer(re.escape('{__$$R$$__:'), framework_text):
        keys = _top_level_keys(_literal_at(framework_text, match.start()))
        if '__$$app$$__' in keys:
            result['app_scope_keys'] = keys
            break
    return result


def inspect(archive):
    members = sorted(n for n in archive.namelist()
                     if n.startswith('META/js_watchfaces/') and n.endswith('.js'))
    bundle_text = '\n'.join(archive.read(n).decode('utf-8', 'replace')
                            for n in members)
    framework = archive.read(FRAMEWORK).decode('utf-8', 'replace')
    return {
        'sandbox': sandbox_contract(framework),
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
