import unittest
from analysis_scripts.zos_api_table import Literal, api_table, summarize

# Synthetic runtime fragment shaped like the minified configuration.
FRAGMENT = (
    'function ge(e,t,n="2.0"){return[{},{}]}'
    'const[Aa,Ab]=ge(ae.hmUI,"hmUI","2.0"),[Ba,Bb]=ge(ae.hmBle,"hmBle","2.0");'
    'const Al={methods:{set:{main:{func:["hmApp","newAlarm"]},version:{"3.0":[]},'
    'permissionCode:"device:os.alarm"},cancel:{main:{func:["hmApp","cancelAlarm"],'
    'arg:["id"]},version:{"3.0":[{options:["id"]}]},permissionCode:"device:os.alarm"}},'
    'constants:N("hmApp",[{oldName:"repeat_type",newName:"repeat"}])},'
    'Dm={getX:{main:e=>e.split(/[,}]/).length,version:{"4.0":[],"2.0":[]}},'
    'helper(){return"}"}},'
    'Ui={methods:Aa,constants:()=>Ab},'
    'Bl={methods:Object.assign({fix:{main:{func:["hmBle","mstDestoryX"],opts:{argType:2}},'
    'version:{"2.0":[]}}},Ba),classes:{TransferFile:Q,HR:{classFunc:Q,permissionCode:"data:user.hd.heart_rate"}},constants:()=>Bb},'
    'Tr={modules:{alarm:Al,demo:{methods:Dm},ui:Ui,ble:Bl,_internals:{methods:{}}}};')


class LiteralTest(unittest.TestCase):
    def test_values(self):
        value, end = Literal('{a:1,"b":[!0,!1,"x"],c:2.5,d:foo,e:()=>1}').value(0)
        self.assertEqual(value['a'], 1)
        self.assertEqual(value['b'], [True, False, 'x'])
        self.assertEqual(value['c'], 2.5)
        self.assertEqual(value['d'], {'ref': 'foo'})
        self.assertIn('code', value['e'])
        self.assertEqual(end, 41)


class ApiTableTest(unittest.TestCase):
    def setUp(self):
        self.modules = api_table(FRAGMENT)

    def test_native_bindings_permissions_and_versions(self):
        alarm = {m['name']: m for m in self.modules['alarm']['methods']}
        self.assertEqual(alarm['set']['native'], 'hmApp.newAlarm')
        self.assertEqual(alarm['cancel']['args'], ['id'])
        self.assertEqual(alarm['cancel']['permission'], 'device:os.alarm')
        self.assertEqual(alarm['set']['since'], '3.0')
        self.assertEqual(self.modules['alarm']['constants_from_call'], 'N')

    def test_javascript_methods_survive_regex_and_strings(self):
        demo = {m['name']: m for m in self.modules['demo']['methods']}
        self.assertEqual(demo['getX']['binding'], 'javascript')
        self.assertEqual(demo['getX']['since'], '2.0')  # earliest version
        self.assertEqual(demo['helper']['binding'], 'opaque')

    def test_reflection_passthrough_and_object_assign(self):
        self.assertEqual(self.modules['ui']['passthrough'],
                         [{'native_object': 'hmUI', 'since': '2.0'}])
        self.assertEqual(self.modules['ui']['constants_from_native'], 'hmUI')
        ble = self.modules['ble']
        self.assertEqual([m['native'] for m in ble['methods']], ['hmBle.mstDestoryX'])
        self.assertEqual(ble['methods'][0]['arg_type'], 2)
        self.assertEqual(ble['passthrough'][0]['native_object'], 'hmBle')
        self.assertEqual(ble['classes'], ['HR', 'TransferFile'])
        self.assertEqual(ble['class_permissions'], {'HR': 'data:user.hd.heart_rate'})

    def test_summary(self):
        summary = summarize(self.modules)
        self.assertEqual(summary['module_count'], 5)
        self.assertEqual(summary['unresolved_modules'], [])
        self.assertEqual(summary['permissions'],
                         ['data:user.hd.heart_rate', 'device:os.alarm'])
        self.assertEqual(summary['passthrough_modules'],
                         {'ble': ['hmBle'], 'ui': ['hmUI']})
        self.assertEqual(self.modules['_internals']['specifier'], None)


if __name__ == '__main__':
    unittest.main()
