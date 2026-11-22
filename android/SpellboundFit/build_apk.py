#!/usr/bin/env python3
"""Build and sign a real installable SpellboundFit-debug.apk using Android SDK build-tools.

Runs completely offline using aapt2, javac, d8, zipalign, keytool and apksigner.
"""
import argparse
import os
import shutil
import subprocess
import tempfile
import zipfile


def find_sdk_tools(sdk_root: str) -> dict[str, str]:
    android_jar = os.path.join(sdk_root, 'platforms', 'android-35', 'android.jar')
    if not os.path.exists(android_jar):
        raise FileNotFoundError(f'Missing {android_jar}')

    bt_root = os.path.join(sdk_root, 'build-tools')
    versions = sorted(os.listdir(bt_root))
    if not versions:
        raise FileNotFoundError(f'No Android build-tools under {bt_root}')
    bt_dir = os.path.join(bt_root, versions[-1])

    tools = {
        'android_jar': android_jar,
        'aapt2': os.path.join(bt_dir, 'aapt2'),
        'd8': os.path.join(bt_dir, 'd8'),
        'zipalign': os.path.join(bt_dir, 'zipalign'),
        'apksigner': os.path.join(bt_dir, 'apksigner'),
        'javac': shutil.which('javac') or '',
        'keytool': shutil.which('keytool') or '',
    }
    for name, path in tools.items():
        if not path or not os.path.exists(path):
            raise FileNotFoundError(f'Required tool {name!r} not found ({path!r})')
    return tools


def run_checked(cmd: list[str]) -> str:
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f'Command failed ({res.returncode}): {" ".join(cmd)}\n{res.stdout}\n{res.stderr}')
    return res.stdout


def build_debug_apk(project_dir: str, out_apk: str, sdk_root: str) -> str:
    tools = find_sdk_tools(sdk_root)
    app_main = os.path.join(project_dir, 'app', 'src', 'main')
    manifest = os.path.join(app_main, 'AndroidManifest.xml')
    res_dir = os.path.join(app_main, 'res')
    java_dir = os.path.join(app_main, 'java')

    os.makedirs(os.path.dirname(os.path.abspath(out_apk)), exist_ok=True)
    keystore = os.path.join(os.path.dirname(os.path.abspath(out_apk)), 'debug.keystore')
    if not os.path.exists(keystore):
        run_checked([
            tools['keytool'], '-genkeypair', '-v',
            '-keystore', keystore,
            '-storepass', 'android', '-keypass', 'android',
            '-alias', 'spellbounddebug',
            '-keyalg', 'RSA', '-keysize', '2048', '-validity', '10000',
            '-dname', 'CN=SpellboundFit Debug,O=SpellboundOS,C=IT',
        ])

    with tempfile.TemporaryDirectory() as tmp:
        res_zip = os.path.join(tmp, 'res.zip')
        gen_java = os.path.join(tmp, 'gen')
        classes_dir = os.path.join(tmp, 'classes')
        dex_dir = os.path.join(tmp, 'dex')
        unaligned_apk = os.path.join(tmp, 'unaligned.apk')
        aligned_apk = os.path.join(tmp, 'aligned.apk')
        os.makedirs(gen_java)
        os.makedirs(classes_dir)
        os.makedirs(dex_dir)

        # 1. Compile Android resources
        run_checked([tools['aapt2'], 'compile', '--dir', res_dir, '-o', res_zip])

        # Prepare manifest with explicit package attribute for standalone aapt2
        with open(manifest, 'r', encoding='utf-8') as mf:
            manifest_xml = mf.read()
        if 'package=' not in manifest_xml:
            manifest_xml = manifest_xml.replace(
                '<manifest ', '<manifest package="dev.spellboundfit" ', 1
            )
        linked_manifest = os.path.join(tmp, 'AndroidManifest.xml')
        with open(linked_manifest, 'w', encoding='utf-8') as mf:
            mf.write(manifest_xml)

        # 2. Link resources + manifest -> base APK + R.java
        run_checked([
            tools['aapt2'], 'link',
            '-I', tools['android_jar'],
            '--manifest', linked_manifest,
            '--java', gen_java,
            '--min-sdk-version', '26',
            '--target-sdk-version', '35',
            '--version-code', '1',
            '--version-name', '0.1.0',
            '-o', unaligned_apk,
            res_zip,
        ])

        # 3. Compile all Java sources + generated R.java
        java_sources = []
        for root_dir in (java_dir, gen_java):
            for dp, _, fns in os.walk(root_dir):
                for fn in fns:
                    if fn.endswith('.java'):
                        java_sources.append(os.path.join(dp, fn))
        run_checked([
            tools['javac'], '--release', '17',
            '-Xlint:all', '-Xlint:-deprecation', '-Werror',
            '-cp', tools['android_jar'],
            '-d', classes_dir,
        ] + java_sources)

        # 4. Convert .class files to Dalvik classes.dex via d8
        class_files = []
        for dp, _, fns in os.walk(classes_dir):
            for fn in fns:
                if fn.endswith('.class'):
                    class_files.append(os.path.join(dp, fn))
        run_checked([
            tools['d8'], '--min-api', '26',
            '--lib', tools['android_jar'],
            '--output', dex_dir,
        ] + class_files)

        # 5. Inject classes.dex into APK
        with zipfile.ZipFile(unaligned_apk, 'a', compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(os.path.join(dex_dir, 'classes.dex'), 'classes.dex')

        # 6. Zipalign + sign with apksigner
        run_checked([tools['zipalign'], '-f', '-p', '4', unaligned_apk, aligned_apk])
        run_checked([
            tools['apksigner'], 'sign',
            '--ks', keystore,
            '--ks-pass', 'pass:android',
            '--key-pass', 'pass:android',
            '--ks-key-alias', 'spellbounddebug',
            '--out', out_apk,
            aligned_apk,
        ])

        # 7. Verify signature & manifest metadata
        run_checked([tools['apksigner'], 'verify', '--verbose', out_apk])
        badging = run_checked([tools['aapt2'], 'dump', 'badging', out_apk])
        return badging


def main() -> None:
    root = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description='Build signed SpellboundFit-debug.apk')
    parser.add_argument('--sdk', default=os.environ.get('ANDROID_HOME', '/home/antona89/Android/Sdk'))
    parser.add_argument('--out', default=os.path.join(root, '..', '..', 'build', 'android', 'SpellboundFit-debug.apk'))
    args = parser.parse_args()

    badging = build_debug_apk(root, args.out, args.sdk)
    print(f'BUILT AND VERIFIED: {os.path.abspath(args.out)}')
    for line in badging.splitlines()[:6]:
        print(' ', line)


if __name__ == '__main__':
    main()
