import unittest
from analysis_scripts.js_runtime_api import (
    parse_banner, module_methods, permission_namespaces, ble_wrapper_methods,
    message_protocol, protocol_constants)

# A synthetic fragment that mimics the shape of the minified runtime without
# reproducing vendor code: a banner, a few native calls, permission strings,
# the framed-message getters and the protocol-header read sequence.
SAMPLE = (
    '/*!\n * project device-runtime-core\n * version v4.2.0-release.1\n'
    ' * api_level 4.2\n * commit abc1234\n */\n'
    'hmApp.startApp(x);hmApp.postNotification(y);hmFS.open(p);hmFS.close(p);'
    'this.ble.mstConnect(a);this.ble.transferFile(b);'
    '"device:os.notification";"device:os.geolocation";"data:os.device.info";'
    'get messageSize(){return 3600}get messagePayloadSize(){return 3584}'
    'get messageHeaderSize(){return 16}'
    'getProtocolHeader(e){const t=q.Buffer.from(e);let n=0;'
    'const r=t.readUInt8(n);n+=1;const s=t.readUInt8(n);n+=1;'
    'const i=t.readUInt16LE(n);n+=2;const o=t.readUInt16LE(n);n+=2;'
    'const a=t.readUInt16LE(n);n+=2;const c=t.readUInt32LE(n);n+=4;'
    'const u=t.readUInt32LE(n);return n+=4,{flag:r,version:s,type:i,'
    'port1:o,port2:a,appId:c,extra:u}}encode(e){}'
    'const U=1,M=0,G=1,k=2,W=1;')


class JsRuntimeApiTest(unittest.TestCase):
    def test_banner(self):
        banner = parse_banner(SAMPLE)
        self.assertEqual(banner['version'], 'v4.2.0-release.1')
        self.assertEqual(banner['api_level'], '4.2')
        self.assertEqual(banner['project'], 'device-runtime-core')

    def test_module_methods_sorted_unique(self):
        self.assertEqual(module_methods(SAMPLE, 'hmApp'),
                         ['postNotification', 'startApp'])
        self.assertEqual(module_methods(SAMPLE, 'hmFS'), ['close', 'open'])

    def test_permissions_and_ble(self):
        self.assertEqual(permission_namespaces(SAMPLE),
                         ['data:os.device.info', 'device:os.geolocation',
                          'device:os.notification'])
        self.assertEqual(ble_wrapper_methods(SAMPLE),
                         ['mstConnect', 'transferFile'])

    def test_message_protocol_header_layout(self):
        proto = message_protocol(SAMPLE)
        self.assertEqual(proto['sizes'],
                         {'message_size': 3600, 'payload_size': 3584,
                          'header_size': 16})
        fields = [(h['field'], h['offset'], h['bytes']) for h in proto['header']]
        self.assertEqual(fields, [
            ('flag', 0, 1), ('version', 1, 1), ('type', 2, 2),
            ('port1', 4, 2), ('port2', 6, 2), ('appId', 8, 4), ('extra', 12, 4)])
        # Header fields account for exactly the declared header size.
        self.assertEqual(proto['header'][-1]['offset'] + proto['header'][-1]['bytes'],
                         proto['sizes']['header_size'])

    def test_protocol_constants(self):
        consts = protocol_constants(SAMPLE)
        self.assertEqual(consts['is_invoke_protocol1'],
                         {'flag': 0, 'type': 1, 'version': 1})
        self.assertEqual(consts['is_close_protocol1'],
                         {'flag': 0, 'type': 2, 'version': 1})


if __name__ == '__main__':
    unittest.main()
