import unittest

from analysis_scripts.clock_cache import (
    cache_contract, cpu_rate, delay_cycle_target, pll_rate, stable_counter,
)


class ClockCacheTest(unittest.TestCase):
    def test_stable_snapshot_retries_a_high_word_rollover(self):
        samples = [(0, 0xffffffff, 1), (1, 3, 1)]
        self.assertEqual(stable_counter(samples), 0x100000003)
        self.assertEqual(stable_counter([(0xffffffff, 0xffffffff, 0xffffffff)]), 2**64 - 1)

    def test_snapshot_host_attempt_and_word_bounds(self):
        for samples in ([], [(0, 0, 1)] * 128 + [(1, 0, 1)], [(0, -1, 0)]):
            with self.assertRaises(ValueError):
                stable_counter(samples)

    def test_fallback_role_specific_dividers_and_bypass(self):
        self.assertEqual(cpu_rate(0, 0), 24000000)
        self.assertEqual(cpu_rate(1, 0), 24000000)
        self.assertEqual(cpu_rate(0, 0x1000000), 48000000)
        self.assertEqual(cpu_rate(1, 0x100), 48000000)
        self.assertEqual(cpu_rate(0, 3 << 4), 9600000)
        self.assertEqual(cpu_rate(1, 3 << 4), 6000000)

    def test_pll_selection_and_postdivider_remapping(self):
        pll_a = (1 << 21) | (1 << 24)
        pll_b = (1 << 16) | (3 << 21) | (1 << 27)
        self.assertEqual(pll_rate(pll_a), 768000000)
        self.assertEqual(pll_rate((1 << 21) | (2 << 24)), 512000000)
        self.assertEqual(cpu_rate(1, 0x103, pll_a=pll_a), 768000000)
        self.assertEqual(cpu_rate(0, 0x1000002, pll_b=pll_b), 528000000)

    def test_invalid_pll_and_role_inputs_fail(self):
        for value in (0, 1 << 21):
            with self.assertRaises(ValueError):
                pll_rate(value)
        with self.assertRaises(ValueError):
            cpu_rate(2, 0)
        with self.assertRaises(ValueError):
            cpu_rate(0, 2)

    def test_delay_target_truncation_and_32_bit_product_wrap(self):
        self.assertEqual(delay_cycle_target(9999999, 100), 900)
        self.assertEqual(delay_cycle_target(4000000000, 1073742), 704)
        with self.assertRaises(ValueError):
            delay_cycle_target(48000000, -1)

    def test_signed_cache_guard_skips_all_recovered_shared_pools(self):
        for start in (0, 0x80000000, 0x80f00000, 0x80f05000, 0x80f0a000, 0xffffffff):
            self.assertEqual(cache_contract(start, 64, enabled=True, command=1),
                             dict(path='skip_signed_nonpositive'))
        self.assertEqual(cache_contract(0x7fffffff, 1, enabled=False, command=1), dict(path='fence_only'))

    def test_cache_disabled_gate_and_initial_alignment(self):
        self.assertEqual(cache_contract(0x1003, 64, enabled=False, command=2), dict(path='fence_only'))
        result = cache_contract(0x1003, 64, enabled=True, command=2)
        self.assertEqual((result['begin'], result['end'], result['command']), (0x1000, 0x1043, 2))
        with self.assertRaises(ValueError):
            cache_contract(0x1000, 64, enabled=True, command=6)

    def test_zero_size_still_enters_command_loop_and_end_wraps(self):
        result = cache_contract(1, 0, enabled=True, command=0)
        self.assertEqual((result['begin'], result['end'], result['minimum_commands']), (0, 1, 1))
        result = cache_contract(0x1000, 0xfffff000, enabled=True, command=1)
        self.assertEqual(result['end'], 0)


if __name__ == '__main__':
    unittest.main()
