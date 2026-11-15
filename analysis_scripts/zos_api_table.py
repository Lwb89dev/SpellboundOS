#!/usr/bin/env python3
"""Extract the declarative ``@zos/*`` API table from the shipped runtime.

``framework.js`` builds the object behind ``__$$R$$__('@zos/<module>')`` from a
configuration literal ``{modules:{router:…, fs:…, ui:…, …}}``. Each module lists
``methods`` (each with a ``main`` binding, optional ``permissionCode`` and a
``version`` map), plus ``constants`` and ``classes``. A ``main`` binding is
either ``{func:["hmApp","newAlarm"], arg:[…], opts:{argType:N}}``, a direct
native call path, or a JavaScript function.

This tool parses those literals statically with a small, conservative JS-literal
reader. Identifiers that name other top-level literals are resolved, and
``Object.assign(...)`` merges are followed. Anything that is code (functions,
arbitrary expressions) is recorded as opaque. Nothing is evaluated.
"""
import argparse
import hashlib
import json
import re
import zipfile

FRAMEWORK = 'META/js_apps/framework.js'
PASSTHROUGH = '\0passthrough'
UNRESOLVED = '\0unresolved'
DELIMS = ',}])'
IDENT = re.compile(r'[A-Za-z_$][\w$]*')
REGEX_PRECEDERS = set('(,=:[!&|?{};+-*%<>~^')


class Opaque(dict):
    """Marker for code or expressions the reader does not interpret."""


class Literal:
    def __init__(self, text):
        self.t = text

    # ---- low-level scanning --------------------------------------------------
    def ws(self, i):
        while i < len(self.t) and self.t[i] in ' \t\r\n':
            i += 1
        return i

    def string_end(self, i):
        quote, i = self.t[i], i + 1
        while self.t[i] != quote:
            i += 2 if self.t[i] == '\\' else 1
        return i + 1

    def template_end(self, i):
        i += 1
        while self.t[i] != '`':
            if self.t[i] == '\\':
                i += 2
            elif self.t.startswith('${', i):
                i = self.balanced_end(i + 1)
            else:
                i += 1
        return i + 1

    def regex_end(self, i):
        i, in_class = i + 1, False
        while True:
            c = self.t[i]
            if c == '\\':
                i += 2
                continue
            if c == '[':
                in_class = True
            elif c == ']':
                in_class = False
            elif c == '/' and not in_class:
                i += 1
                break
            i += 1
        while i < len(self.t) and (self.t[i].isalnum()):
            i += 1
        return i

    def _prev_significant(self, i):
        j = i - 1
        while j >= 0 and self.t[j] in ' \t\r\n':
            j -= 1
        return self.t[j] if j >= 0 else '('

    def skip_token(self, i):
        c = self.t[i]
        if c in '"\'':
            return self.string_end(i)
        if c == '`':
            return self.template_end(i)
        if c == '/' and self._prev_significant(i) in REGEX_PRECEDERS:
            return self.regex_end(i)
        return i + 1

    def balanced_end(self, i):
        """Index after the bracket group opening at ``i``."""
        depth = 0
        while True:
            c = self.t[i]
            if c in '([{':
                depth += 1
                i += 1
            elif c in ')]}':
                depth -= 1
                i += 1
                if depth == 0:
                    return i
            else:
                i = self.skip_token(i)

    def expression_end(self, i):
        while i < len(self.t):
            c = self.t[i]
            if c in DELIMS or c == ';':
                return i
            if c in '([{':
                i = self.balanced_end(i)
            else:
                i = self.skip_token(i)
        return i

    # ---- values --------------------------------------------------------------
    def value(self, i):
        i = self.ws(i)
        c = self.t[i]
        if c == '{':
            return self.obj(i)
        if c == '[':
            return self.arr(i)
        if c in '"\'':
            end = self.string_end(i)
            if self.t[self.ws(end)] in DELIMS:
                return json.loads(self._json_string(self.t[i:end])), end
        number = re.match(r'-?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?', self.t[i:])
        if number and self.t[self.ws(i + number.end())] in DELIMS:
            text = number.group()
            return (float(text) if re.search(r'[.e]', text) else int(text)), i + number.end()
        boolean = re.match(r'!([01])', self.t[i:])
        if boolean and self.t[self.ws(i + 2)] in DELIMS:
            return boolean.group(1) == '0', i + 2
        return self.expression(i)

    @staticmethod
    def _json_string(raw):
        if raw[0] == "'":
            raw = '"' + raw[1:-1].replace('\\\'', "'").replace('"', '\\"') + '"'
        return raw

    def expression(self, i):
        end = self.expression_end(i)
        text = self.t[i:end].strip()
        if IDENT.fullmatch(text) and text not in ('void', 'null', 'undefined'):
            return Opaque(ref=text), end
        getter = re.fullmatch(r'\(\)=>([A-Za-z_$][\w$]*)', text)
        if getter:  # `()=>X` constant getters are followed to X
            return Opaque(ref=getter.group(1)), end
        call = re.match(r'([\w$.]+)\(', text)
        if call and self.balanced_end(i + call.end() - 1) == end:
            args, j = [], self.ws(i + call.end())
            try:
                while self.t[j] != ')':
                    value, j = self.value(j)
                    args.append(value)
                    j = self.ws(j)
                    if self.t[j] == ',':
                        j = self.ws(j + 1)
                return Opaque(call=call.group(1), args=args), end
            except (IndexError, ValueError, json.JSONDecodeError):
                pass
        return Opaque(code=text[:80]), end

    def arr(self, i):
        out, i = [], self.ws(i + 1)
        while self.t[i] != ']':
            if self.t.startswith('...', i):
                value, i = self.value(i + 3)
                out.append(Opaque(spread=value))
            else:
                value, i = self.value(i)
                out.append(value)
            i = self.ws(i)
            if self.t[i] == ',':
                i = self.ws(i + 1)
        return out, i + 1

    def obj(self, i):
        out, i = {}, self.ws(i + 1)
        while self.t[i] != '}':
            if self.t.startswith('...', i):
                value, i = self.value(i + 3)
                out.setdefault('...', []).append(value)
            elif self.t[i] == '[':  # computed key: keep as opaque entry
                key_end = self.balanced_end(i)
                key = self.t[i:key_end]
                i = self.ws(key_end)
                if self.t[i] == ':':
                    value, i = self.value(i + 1)
                else:
                    i = self._method_end(i)
                    value = Opaque(code='method')
                out[key] = value
            else:
                if self.t[i] in '"\'':
                    end = self.string_end(i)
                    key = json.loads(self._json_string(self.t[i:end]))
                else:
                    match = re.match(r'(?:async\s+|get\s+|set\s+|\*)?([\w$.]+)', self.t[i:])
                    key, end = match.group(1), i + match.end()
                j = self.ws(end)
                if self.t[j] == ':':
                    out[key], i = self.value(j + 1)
                elif self.t[j] == '(':
                    out[key], i = Opaque(code='method'), self._method_end(j)
                else:  # shorthand property
                    out[key], i = Opaque(ref=key), j
            i = self.ws(i)
            if self.t[i] == ',':
                i = self.ws(i + 1)
        return out, i + 1

    def _method_end(self, i):
        i = self.ws(self.balanced_end(i))  # parameters
        return self.balanced_end(i)        # body


class Resolver:
    """Resolve identifiers to top-level literal definitions in the file."""

    # `[methods, constants] = ge(ae.hmUI, "hmUI", "2.0")`: at runtime ge() turns
    # every function property of the native object into a method bound to it
    # (argType 2) and every other property into a constant.
    REFLECTION = re.compile(r'\[([\w$]+),([\w$]+)\]=ge\(ae\.(\w+),"(\w+)","([\d.]+)"\)')

    def __init__(self, text):
        self.text = text
        self.reader = Literal(text)
        self.cache = {}
        for match in self.REFLECTION.finditer(text):
            methods, constants, _, native, since = match.groups()
            self.cache[methods] = Opaque(passthrough=native, since=since)
            self.cache[constants] = Opaque(passthrough_constants=native)

    def definition(self, name):
        if name in self.cache:
            return self.cache[name]
        self.cache[name] = None  # break cycles
        pattern = re.compile(r'(?:\bconst\s+|\blet\s+|\bvar\s+|[,;{])' +
                             re.escape(name) + r'=(?![=>])')
        for match in pattern.finditer(self.text):
            start = match.end()
            if self.text[start] not in '{[':
                if not self.text.startswith('Object.assign(', start):
                    continue
            try:
                value, _ = self.reader.value(start)
            except (IndexError, ValueError, json.JSONDecodeError):
                continue
            self.cache[name] = value
            return value
        return None

    def resolve(self, node, depth=0):
        if depth > 12:
            return node
        if isinstance(node, Opaque):
            if 'ref' in node:
                target = self.definition(node['ref'])
                return node if target is None else self.resolve(target, depth + 1)
            if node.get('call') == 'Object.assign':
                merged, passthrough = {}, []
                for arg in node['args']:
                    value = self.resolve(arg, depth + 1)
                    if isinstance(value, Opaque) and 'passthrough' in value:
                        passthrough.append(value)
                    elif isinstance(value, dict) and not isinstance(value, Opaque):
                        merged.update(value)
                        passthrough.extend(merged.pop(PASSTHROUGH, []))
                    else:
                        merged.setdefault(UNRESOLVED, []).append(value)
                if passthrough:
                    merged[PASSTHROUGH] = passthrough
                return merged
            return node
        if isinstance(node, dict):
            return {k: self.resolve(v, depth + 1) for k, v in node.items()}
        if isinstance(node, list):
            return [self.resolve(v, depth + 1) for v in node]
        return node


def config_literal(text):
    """Locate the ``{modules:{…}}`` API configuration literal."""
    match = re.search(r'=\{modules:\{', text)
    if not match:
        raise ValueError('API configuration literal not found')
    value, _ = Literal(text).value(match.start() + 1)
    return value


def describe_method(name, spec):
    entry = {'name': name}
    if not isinstance(spec, dict) or isinstance(spec, Opaque):
        entry['binding'] = 'opaque'
        return entry
    main = spec.get('main')
    if isinstance(main, dict) and not isinstance(main, Opaque):
        func = main.get('func')
        if isinstance(func, list) and all(isinstance(x, str) for x in func):
            entry['binding'] = 'native'
            entry['native'] = '.'.join(func)
        else:
            entry['binding'] = 'opaque'
        if isinstance(main.get('arg'), list):
            entry['args'] = [a for a in main['arg'] if isinstance(a, str)]
        opts = main.get('opts')
        if isinstance(opts, dict) and isinstance(opts.get('argType'), int):
            entry['arg_type'] = opts['argType']
    else:
        entry['binding'] = 'javascript'
    permission = spec.get('permissionCode')
    if isinstance(permission, str):
        entry['permission'] = permission
    elif permission is not None:
        entry['permission'] = 'unresolved'
    versions = spec.get('version')
    if isinstance(versions, dict) and not isinstance(versions, Opaque):
        entry['since'] = sorted(versions, key=lambda v: [int(x) for x in v.split('.')])[0] \
            if all(re.fullmatch(r'\d+(\.\d+)*', v) for v in versions) else sorted(versions)
    return entry


def api_table(text):
    resolver = Resolver(text)
    config = resolver.resolve(config_literal(text))
    modules = {}
    for module, spec in sorted(config.get('modules', {}).items()):
        entry = {'specifier': f'@zos/{module}' if not module.startswith('_') else None}
        if not isinstance(spec, dict) or isinstance(spec, Opaque):
            entry['unresolved'] = True
            modules[module] = entry
            continue
        methods = spec.get('methods')
        if isinstance(methods, Opaque) and 'passthrough' in methods:
            methods = {PASSTHROUGH: [methods]}
        if isinstance(methods, dict) and not isinstance(methods, Opaque):
            passthrough = methods.get(PASSTHROUGH, [])
            if passthrough:
                entry['passthrough'] = [{'native_object': p['passthrough'],
                                         'since': p['since']} for p in passthrough]
            if methods.get(UNRESOLVED):
                entry['methods_partially_unresolved'] = True
            entry['methods'] = [describe_method(n, s) for n, s in sorted(methods.items())
                                if n not in (PASSTHROUGH, UNRESOLVED)]
        elif methods is not None:
            entry['methods_unresolved'] = True
        constants = spec.get('constants')
        if isinstance(constants, dict) and not isinstance(constants, Opaque):
            entry['constants'] = sorted(constants)
        elif isinstance(constants, Opaque) and constants.get('call'):
            entry['constants_from_call'] = constants['call']
        elif isinstance(constants, Opaque) and 'passthrough_constants' in constants:
            entry['constants_from_native'] = constants['passthrough_constants']
        classes = spec.get('classes')
        if isinstance(classes, dict) and not isinstance(classes, Opaque):
            entry['classes'] = sorted(classes)
            permissions = {name: spec_.get('permissionCode') for name, spec_ in classes.items()
                           if isinstance(spec_, dict) and not isinstance(spec_, Opaque)
                           and isinstance(spec_.get('permissionCode'), str)}
            if permissions:
                entry['class_permissions'] = dict(sorted(permissions.items()))
        modules[module] = entry
    return modules


def summarize(modules):
    methods = [m for e in modules.values() for m in e.get('methods', [])]
    natives = sorted({m['native'] for m in methods if m.get('native')})
    return {
        'module_count': len(modules),
        'method_count': len(methods),
        'native_bound_methods': sum(m['binding'] == 'native' for m in methods),
        'javascript_methods': sum(m['binding'] == 'javascript' for m in methods),
        'opaque_methods': sum(m['binding'] == 'opaque' for m in methods),
        'unresolved_modules': sorted(k for k, e in modules.items()
                                     if e.get('unresolved') or e.get('methods_unresolved')
                                     or e.get('methods_partially_unresolved')),
        'passthrough_modules': {k: [p['native_object'] for p in e['passthrough']]
                                for k, e in sorted(modules.items()) if e.get('passthrough')},
        'distinct_native_targets': natives,
        'permissions': sorted({m['permission'] for m in methods if m.get('permission')}
                              | {p for e in modules.values()
                                 for p in e.get('class_permissions', {}).values()}),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        data = archive.read(FRAMEWORK)
    text = data.decode('utf-8', 'replace')
    modules = api_table(text)
    print(json.dumps({'member': FRAMEWORK, 'sha256': hashlib.sha256(data).hexdigest(),
                      'summary': summarize(modules), 'modules': modules},
                     indent=2, sort_keys=True, ensure_ascii=True))


if __name__ == '__main__':
    main()
