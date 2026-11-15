import unittest
from analysis_scripts.app_model import (
    injected_globals, runtime_entry_points, lifecycle_hooks)

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


if __name__ == '__main__':
    unittest.main()
