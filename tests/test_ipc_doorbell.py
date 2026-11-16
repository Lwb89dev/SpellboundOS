import unittest

from analysis_scripts.ipc_doorbell import (
    critical_step, irq_bank, queue_token, receive_notice, should_notify, wait_expired,
)


class IpcDoorbellTest(unittest.TestCase):
    def test_six_queues_route_in_both_roles_and_ack_after_dispatch(self):
        for role in (0, 1):
            for queue in range(6):
                result = receive_notice(role, queue_token(queue))
                self.assertEqual(result['queue'], queue)
                self.assertEqual(result['register'], 0x9000807c if role == 0 else 0x90008074)
                self.assertEqual(result['steps'], ['dispatch', 'echo_ack'])

    def test_exception_token_is_role_specific_and_acknowledged_first(self):
        result = receive_notice(0, 0xff)
        self.assertIsNone(result['queue'])
        self.assertEqual(result['steps'], ['echo_ack', 'exception_path'])
        with self.assertRaises(ValueError):
            receive_notice(1, 0xff)

    def test_notice_and_callback_index_bounds(self):
        self.assertEqual(receive_notice(0, queue_token(31))['queue'], 31)
        for role, word in ((0, 0), (0, 33), (1, 33), (2, 1), (0, -1)):
            with self.assertRaises(ValueError):
                receive_notice(role, word)
        with self.assertRaises(ValueError):
            queue_token(32)

    def test_irq_bank_bit_boundaries(self):
        self.assertEqual(irq_bank(16), dict(address=0xe4002000, mask=0x10000))
        self.assertEqual(irq_bank(31), dict(address=0xe4002000, mask=0x80000000))
        self.assertEqual(irq_bank(32), dict(address=0xe4002004, mask=1))
        self.assertEqual(irq_bank(82), dict(address=0xe4002008, mask=1 << 18))
        for value in (-1, 83, 0x10000010):
            with self.assertRaises(ValueError):
                irq_bank(value)

    def test_nested_critical_sections_only_change_irq_at_outer_boundary(self):
        self.assertEqual(critical_step(0, enter=True), dict(count=1, irq_action='disable'))
        self.assertEqual(critical_step(1, enter=True), dict(count=2, irq_action=None))
        self.assertEqual(critical_step(2, enter=False), dict(count=1, irq_action=None))
        self.assertEqual(critical_step(1, enter=False), dict(count=0, irq_action='enable'))

    def test_unbalanced_or_overflowing_counter_is_rejected(self):
        for count, enter in ((0, False), (-1, True), (0x7fffffff, True)):
            with self.assertRaises(ValueError):
                critical_step(count, enter=enter)

    def test_flag_based_notification_suppression(self):
        self.assertTrue(should_notify(added=1, available_index=1))
        self.assertFalse(should_notify(added=1, available_index=1, used_flags=1))
        self.assertTrue(should_notify(added=1, available_index=1, used_flags=2))

    def test_event_index_threshold_and_wrap(self):
        self.assertTrue(should_notify(added=1, available_index=8, event_index=7))
        self.assertFalse(should_notify(added=1, available_index=8, event_index=6))
        self.assertTrue(should_notify(added=2, available_index=8, event_index=6))
        self.assertTrue(should_notify(added=1, available_index=0, event_index=0xffff))
        self.assertFalse(should_notify(added=0, available_index=0, event_index=0xffff))
        with self.assertRaises(ValueError):
            should_notify(added=1, available_index=65536)

    def test_wait_boundary_and_unsigned_64_bit_wrap(self):
        self.assertFalse(wait_expired(100, 1099))
        self.assertTrue(wait_expired(100, 1100))
        start = 2**64 - 500
        self.assertFalse(wait_expired(start, 499))
        self.assertTrue(wait_expired(start, 500))
        with self.assertRaises(ValueError):
            wait_expired(-1, 0)


if __name__ == '__main__':
    unittest.main()
