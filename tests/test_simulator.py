"""End-to-end tests for the desktop SpellboundOS C-kernel watch simulator."""
import os
import tempfile
import unittest

from companion.cli import generate_demo_screenshots
from companion.protocol import CallState, MsgType, decode_notify_action, decode_telemetry
from companion.simulator import (
    KEY_DOUBLE_CLICK,
    KEY_SHORT_CLICK,
    SCREEN_NAVIGATION,
    SCREEN_NOTIFICATIONS,
    WatchSimulator,
)


class WatchSimulatorTest(unittest.TestCase):
    def test_full_encrypted_simulator_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            sim = WatchSimulator(so_path=os.path.join(tmp, 'libsim.so'))
            self.assertEqual((sim.width, sim.height), (390, 450))
            sim.establish_secure_link()

            # Encrypted PING -> PONG
            replies = sim.ping()
            self.assertEqual([r.msg_type for r in replies], [MsgType.PONG])

            # Sync time, send notification with action, click -> Notifications, double-click -> Action
            sim.sync_time(1795255200, 60)
            ack = sim.send_notification(101, 'WhatsApp', 'Giulia', 'Pronto?', actions=['Si', 'No'])
            self.assertEqual([r.msg_type for r in ack], [MsgType.ACK])
            self.assertTrue(sim.lib.sim_motor_active())

            sim.press_key(KEY_SHORT_CLICK, 0)
            sim.step(10)
            self.assertEqual(sim.lib.sim_current_screen(), SCREEN_NOTIFICATIONS)

            sim.press_key(KEY_DOUBLE_CLICK, 0)
            out = sim.step(10)
            action_frames = [f for f in out if f.msg_type == MsgType.NOTIFY_ACTION]
            self.assertEqual(len(action_frames), 1)
            act = decode_notify_action(action_frames[0].payload)
            self.assertEqual((act.notif_id, act.action_index), (101, 0))

            # Roadstr Italian turn-by-turn notification auto-promotes Navigation screen
            sim.send_roadstr('Svolta a sinistra', 'Svolta a sinistra tra 250 m su Via Roma (Arrivo 6 min)')
            sim.step(10)
            self.assertEqual(sim.lib.sim_current_screen(), SCREEN_NAVIGATION)

            # Simulate walking + ALS + battery -> encrypted telemetry report
            sim.lib.sim_inject_battery(76, False)
            sim.lib.sim_inject_hr(82)
            sim.lib.sim_inject_als(5000)
            sim.simulate_walk(5)
            out = sim.step(500)
            tel_frames = [f for f in out if f.msg_type == MsgType.TELEMETRY]
            self.assertGreaterEqual(len(tel_frames), 1)
            tel = decode_telemetry(tel_frames[-1].payload)
            self.assertEqual(tel.battery_pct, 76)
            self.assertEqual(tel.hr_bpm, 82)
            self.assertGreaterEqual(tel.steps, 5)
            self.assertEqual(sim.lib.sim_brightness(), 255)

            # Interactive shell works over live watch state
            nav_out = sim.shell('nav status')
            self.assertIn('TURN LEFT', nav_out)
            self.assertIn('Via Roma', nav_out)

    def test_demo_screenshots_render_valid_pngs(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = generate_demo_screenshots(tmp)
            self.assertEqual(len(files), 6)
            for path in files:
                with open(path, 'rb') as f:
                    data = f.read()
                self.assertTrue(data.startswith(b'\x89PNG\r\n\x1a\n'), path)
                self.assertGreater(len(data), 500, path)


if __name__ == '__main__':
    unittest.main()
