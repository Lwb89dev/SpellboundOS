#!/usr/bin/env python3
"""Query Amazfit's public OTA endpoint for this Bip 6; never flash anything.

Request parameters follow https://github.com/otaj/zelp firmware_client.dart.
Results are metadata, not proof of image completeness or installability.
"""
import argparse
import json
import sys
import urllib.parse
import urllib.request

APP = '10.9.0-play_151983'
CV = '151983_10.9.0-play'


def query(country, version):
    params = dict(channel='play', country=country, device='android_35',
                  deviceType='ALL', device_type='android_phone', diagnosticCode='1',
                  firmwareFlag='-1', firmwareVersion=version, fontFlag='0',
                  fontVersion='0', gpsVersion='0', hardwareVersion='0', lang='en_US',
                  productId='0', resourceFlag='-1', resourceVersion='-1',
                  support8Bytes='true', timezone='Europe/Rome', v='2.0',
                  vendorSource='1', appVersion=APP, cv=CV,
                  deviceSource='10158337', productionSource='240')
    headers = {'appname': 'com.huami.midong', 'appplatform': 'android_phone',
               'channel': 'play', 'country': country, 'hm-privacy-ceip': 'false',
               'hm-privacy-diagnostics': 'false', 'lang': 'en_US',
               'timezone': 'Europe/Rome', 'v': '2.0', 'vn': '10.9.0-play',
               'cv': CV, 'user-agent': 'Zepp/10.9.0-play (SM-S921B; Android 15; Density/2.75)'}
    url = 'https://api.amazfit.com/devices/ALL/hasNewVersion?' + urllib.parse.urlencode(params)
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=20) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--countries', nargs='+', default=['IT', 'US', 'PL', 'CN', 'RU'])
    parser.add_argument('--versions', nargs='+', default=['4.6.0.3', '0'])
    args = parser.parse_args()
    results = []
    for country in args.countries:
        for version in args.versions:
            try:
                result = query(country, version)
                results.append({'country': country, 'from': version, 'response': result})
            except Exception as exc:
                results.append({'country': country, 'from': version, 'error': str(exc)})
    print(json.dumps(results, indent=2, ensure_ascii=False))
    if any('error' in item for item in results):
        sys.exit(1)


if __name__ == '__main__':
    main()
