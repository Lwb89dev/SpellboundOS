import unittest
from analysis_scripts.rtos_timer import (
    callback_record, resume_tick_estimate, stable_aon, suspend_alarm_ticks, timer_interrupt, timer_setup,
)


class RtosTimerTest(unittest.TestCase):
    def test_callback_table_records_have_sixteen_byte_stride(self):
        self.assertEqual(callback_record('main',7),0x80c00a64)
        self.assertEqual(callback_record('sensor',7),0x80f15984)
        for value in (-1,16,True):
            with self.assertRaises(ValueError): callback_record('main',value)

    def test_separate_counter_domains(self):
        self.assertEqual(timer_setup(0,'main')['compare'],1000)
        self.assertEqual(timer_setup(0,'sensor')['compare'],33)
        self.assertEqual(timer_setup(100,'sensor')['next_compare'],166)

    def test_setup_write_order_and_word_carry(self):
        result = timer_setup(0xffffffff,'main')
        self.assertEqual(result['writes'],[(0xe6000008,999),(0xe600000c,1)])
        self.assertEqual(result['next_compare'],0x1000007cf)

    def test_periodic_rearm_uses_saved_deadline_and_wraps(self):
        result = timer_interrupt(2**64-1,0,'sensor')
        self.assertEqual(result['writes'],[(0xe6000008,0),(0xe600000c,0xffffffff),(0xe6000008,0xffffffff)])
        self.assertEqual(result['next_compare'],32)

    def test_interrupt_bit_is_set_even_if_previously_clear(self):
        for initial in (0,0x80,0xa5a58000,0xffffffff):
            result = timer_interrupt(100,initial,'main')
            self.assertEqual(result['mie_during'],initial & ~0x80)
            self.assertEqual(result['mie_after'],initial | 0x80)

    def test_aon_requires_complete_pair_agreement(self):
        self.assertEqual(stable_aon([(0xffffffff,3,0,4),(2,4,2,4)]),0x400000002)
        self.assertEqual(stable_aon([(7,3,7,4),(8,4,8,4)]),0x400000008)
        self.assertEqual(stable_aon([(7,3,7,3)]),0x300000007)

    def test_aon_host_bound_and_word_validation(self):
        for samples in ([],[(0,0,1,0)]*128+[(2,0,2,0)],[(True,0,0,0)]):
            with self.assertRaises(ValueError): stable_aon(samples)

    def test_suspend_margins_and_short_idle_exclusion(self):
        self.assertEqual(suspend_alarm_ticks(1000,1),32735)
        self.assertEqual(suspend_alarm_ticks(1000,3),32669)
        for idle,margin in ((0,1),(3,1),(4,0),(10,2),(10,True)):
            with self.assertRaises(ValueError): suspend_alarm_ticks(idle,margin)

    def test_suspend_shift_wraps_before_division(self):
        self.assertEqual(suspend_alarm_ticks(131073,1),0)
        self.assertEqual(suspend_alarm_ticks(131074,1),32)
        self.assertNotEqual(suspend_alarm_ticks(131073,1),(131073-1)*32768//1000)

    def test_resume_conversion_preserves_fixed_width(self):
        self.assertEqual(resume_tick_estimate(32),0)
        self.assertEqual(resume_tick_estimate(33),1)
        self.assertEqual(resume_tick_estimate(32768),1000)
        self.assertEqual(resume_tick_estimate(2**64-1),0xffffffff)

    def test_invalid_unsigned_inputs_and_domain(self):
        for invalid in (-1,2**64,True,1.0):
            for call in (lambda:timer_setup(invalid,'main'),lambda:timer_interrupt(invalid,0,'main'),
                         lambda:resume_tick_estimate(invalid)):
                with self.assertRaises(ValueError): call()
        with self.assertRaises(ValueError): timer_setup(0,'unknown')


if __name__ == '__main__': unittest.main()
