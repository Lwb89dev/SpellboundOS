import unittest
from analysis_scripts.app_model import (
    injected_globals, runtime_entry_points, lifecycle_hooks, sandbox_contract)

FRAMEWORK_SAMPLE = (
    'const et=["globalThis","window"],tt=["hmUI","__loadScript","eval"],'
    'nt={undefined:!0,Math:!0,Promise:!1};'
    'const{__$$R$$__:r}=t.__globals__,s={__$$R$$__:r,__$$app$$__:t,'
    'App:We,getApp:()=>t.app,getCurrentPage:()=>t.current&&t.current.module,'
    'getAppContext:()=>({a:1,b:2})};')

SAMPLE = (
    'var __$$app$$__ = __$$hmAppManager$$__.currentApp;'
    'var __$$module$$__ = __$$app$$__.current;'
    'var h = new DeviceRuntimeCore.WidgetFactory('
    'new DeviceRuntimeCore.HmDomApi(__$$app$$__, __$$module$$__), "drink");'
    '__$$app$$__.app = DeviceRuntimeCore.App({'
    'onCreate(o){}, onShow(o){}, onDestory(o){}, onError:function(e){}});')


class AppModelTest(unittest.TestCase):
    def test_injected_globals(self):
        self.assertEqual(injected_globals(SAMPLE),
                         ['app', 'hmAppManager', 'module'])

    def test_entry_points(self):
        self.assertEqual(runtime_entry_points(SAMPLE),
                         ['App', 'HmDomApi', 'WidgetFactory'])

    def test_lifecycle_hooks_method_and_property_forms(self):
        # Matches both `onShow(o){}` and `onError:function(){}`.
        self.assertEqual(lifecycle_hooks(SAMPLE),
                         ['onCreate', 'onDestory', 'onError', 'onShow'])

    def test_sandbox_contract(self):
        sandbox = sandbox_contract(FRAMEWORK_SAMPLE)
        self.assertEqual(sandbox['sandbox_hidden_names'],
                         ['hmUI', '__loadScript', 'eval'])
        self.assertEqual(sandbox['global_aliases'], ['globalThis', 'window'])
        self.assertEqual(sandbox['unscopables'],
                         {'undefined': True, 'Math': True, 'Promise': False})
        # Skips the destructuring pattern; ignores keys inside nested values.
        self.assertEqual(sandbox['app_scope_keys'],
                         ['__$$R$$__', '__$$app$$__', 'App', 'getApp',
                          'getCurrentPage', 'getAppContext'])


if __name__ == '__main__':
    unittest.main()
